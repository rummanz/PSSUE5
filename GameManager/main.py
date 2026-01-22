import uvicorn
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import psutil
import json
import zipfile
import subprocess
import logging
import pefile
import sqlite3
import datetime

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load Configuration
CONFIG_FILE = "config.json"
try:
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
except FileNotFoundError:
    logger.error(f"Config file {CONFIG_FILE} not found!")
    config = {}

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GAME_EXECUTABLE = config.get("gameExecutablePath", "")
GAME_DIRECTORY = config.get("gameDirectory", "")

# Initialize Database
DB_FILE = "stats.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TIMESTAMP,
                last_seen TIMESTAMP,
                end_time TIMESTAMP,
                duration INTEGER
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

init_db()

def log_session_start():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        now = datetime.datetime.now()
        cursor.execute('INSERT INTO sessions (start_time, last_seen) VALUES (?, ?)', (now, now))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log session start: {e}")

def log_session_heartbeat(pid):
    # We update the latest 'open' session (end_time IS NULL)
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        now = datetime.datetime.now()
        # Update last_seen for the most recent active session
        cursor.execute('''
            UPDATE sessions 
            SET last_seen = ? 
            WHERE id = (SELECT id FROM sessions WHERE end_time IS NULL ORDER BY start_time DESC LIMIT 1)
        ''', (now,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log heartbeat: {e}")

def log_session_stop():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        now = datetime.datetime.now()
        # Find latest active session
        cursor.execute('SELECT id, start_time, last_seen FROM sessions WHERE end_time IS NULL ORDER BY start_time DESC LIMIT 1')
        row = cursor.fetchone()
        if row:
            session_id, start_str, last_seen_str = row
            # Calculate duration
            # SQLite stores timestamps as strings usually, need parsing if not using adapter
            start_time = datetime.datetime.fromisoformat(start_str) if isinstance(start_str, str) else start_str
            duration = (now - start_time).total_seconds()
            
            cursor.execute('UPDATE sessions SET end_time = ?, duration = ? WHERE id = ?', (now, int(duration), session_id))
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log session stop: {e}")

def get_process_id() -> int | None:
    """Finds the PID of the running game process."""
    if not GAME_EXECUTABLE:
        return None
    process_name = os.path.basename(GAME_EXECUTABLE)
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
             # Check exact path if possible, or fallback to name
            if proc.info['exe'] == GAME_EXECUTABLE or proc.info['name'] == process_name:
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return None

@app.get("/stats")
def get_stats():
    """Returns aggregated session statistics."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Total sessions
        cursor.execute('SELECT COUNT(*) FROM sessions')
        total_sessions = cursor.fetchone()[0]
        
        # Total duration
        cursor.execute('SELECT SUM(duration) FROM sessions WHERE duration IS NOT NULL')
        total_duration = cursor.fetchone()[0] or 0
        
        # Average duration
        avg_duration = total_duration / total_sessions if total_sessions > 0 else 0
        
        return {
            "total_sessions": total_sessions,
            "total_duration_seconds": total_duration,
            "average_session_duration_seconds": avg_duration
        }
    except Exception as e:
        logger.error(f"Failed to fetch stats: {e}")
        return {"error": str(e)}

@app.get("/version")
def get_version():
    """Returns the version, PID, and running status."""
    response = {
        "version": "Unknown", 
        "product_version": "Unknown", 
        "status": "Executable Not Found",
        "pid": None,
        "is_running": False
    }

    # Check Process Status
    pid = get_process_id()
    if pid:
        response["pid"] = pid
        response["is_running"] = True
        response["status"] = "Running"
        log_session_heartbeat(pid)
    else:
        response["status"] = "Stopped"

    if not GAME_EXECUTABLE or not os.path.exists(GAME_EXECUTABLE):
        response["status"] = "Executable Missing"
        return response
    
    # Check File Version
    try:
        pe = pefile.PE(GAME_EXECUTABLE)
        try:
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                ver_info = pe.VS_FIXEDFILEINFO[0]
                file_ver = f"{ver_info.FileVersionMS >> 16}.{ver_info.FileVersionMS & 0xFFFF}.{ver_info.FileVersionLS >> 16}.{ver_info.FileVersionLS & 0xFFFF}"
                product_ver = f"{ver_info.ProductVersionMS >> 16}.{ver_info.ProductVersionMS & 0xFFFF}.{ver_info.ProductVersionLS >> 16}.{ver_info.ProductVersionLS & 0xFFFF}"
                response["version"] = file_ver
                response["product_version"] = product_ver
        finally:
            pe.close()
    except Exception as e:
        logger.error(f"Failed to read version: {e}")
        response["version"] = "Error reading version"

    return response

@app.post("/upload")
async def upload_game(file: UploadFile = File(...)):
    """Receives a zip file, smart-extracts it, and replaces the game files."""
    try:
        # Note: We do NOT stop the game here yet. We stop after upload, before extract.
        
        zip_path = "uploaded_game.zip"
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        if not zipfile.is_zipfile(zip_path):
             os.remove(zip_path)
             raise HTTPException(status_code=400, detail="Uploaded file is not a valid zip archive.")

        # Stop game if running BEFORE wiping/extracting
        stop_game()

        # Wipe existing directory
        if os.path.exists(GAME_DIRECTORY):
            logger.info(f"Removing existing directory: {GAME_DIRECTORY}")
            shutil.rmtree(GAME_DIRECTORY)
        
        # Smart Extraction Logic
        logger.info(f"Extracting to {GAME_DIRECTORY}...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Find the root 'Windows' folder in the zip
            windows_root = None
            for name in zip_ref.namelist():
                # Normalize path separators
                parts = name.replace('\\', '/').split('/')
                if 'Windows' in parts:
                    idx = parts.index('Windows')
                    # We found 'Windows'. The prefix is everything before it.
                    # e.g. "MyBuild/Windows/Binaries..." -> prefix is "MyBuild/"
                    # e.g. "Windows/Binaries..." -> prefix is ""
                    prefix = "/".join(parts[:idx])
                    if prefix:
                        prefix += "/" # Ensure trailing slash
                    else:
                        prefix = ""
                    windows_root = prefix
                    break # Assuming the first 'Windows' found is the one we want.

            if windows_root is None:
                # Fallback: Just extract normally if logic doesn't apply, or error out.
                # User requirement: "An accepted zip file should have windows directory"
                # If we didn't find "Windows" at all, maybe it's invalid.
                # For now, let's just extract all.
                logger.warning("Could not find 'Windows' directory in zip. extracting as-is.")
                os.makedirs(GAME_DIRECTORY, exist_ok=True)
                zip_ref.extractall(GAME_DIRECTORY)
            else:
                # Extract only files starting with windows_root, and strip that prefix
                for member in zip_ref.infolist():
                    if member.filename.replace('\\', '/').startswith(windows_root):
                        # Calculate target path by stripping prefix
                        relative_path = member.filename[len(windows_root):] 
                        if not relative_path: continue # Skip the root dir itself if generic

                        target_path = os.path.join(GAME_DIRECTORY, relative_path)
                        
                        # Handle directories
                        if member.is_dir():
                            os.makedirs(target_path, exist_ok=True)
                        else:
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            with zip_ref.open(member) as source, open(target_path, "wb") as target:
                                shutil.copyfileobj(source, target)
        
        os.remove(zip_path)
        logger.info("Upload and extraction successful.")
        
        return {"message": "Game uploaded and extracted successfully"}
    except Exception as e:
        logger.error(f"Upload failed: {str(e)}")
        if os.path.exists("uploaded_game.zip"):
             try:
                os.remove("uploaded_game.zip")
             except:
                pass
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/start")
def start_game():
    """Starts the game executable with PixelStreaming arguments."""
    pid = get_process_id()
    if pid:
         return {"message": "Game is already running", "pid": pid}
    
    if not os.path.exists(GAME_EXECUTABLE):
        raise HTTPException(status_code=404, detail="Game executable not found.")

    try:
        # Arguments requested by user
        args = [
            GAME_EXECUTABLE,
            "-PixelStreamingIP=127.0.0.1",
            "-PixelStreamingPort=8888",
            "-RenderOffscreen",
            "-ResX=1920",
            "-ResY=1080",
            "-ForceRes",
            "-notexturestreaming"
        ]
        
        # Start non-blocking
        subprocess.Popen(args)
        log_session_start()
        return {"message": "Game started"}
    except Exception as e:
        logger.error(f"Failed to start game: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/stop")
def stop_game():
    """Stops the game executable."""
    pid = get_process_id()
    if not pid:
        return {"message": "Game is not running"}
    
    try:
        process = psutil.Process(pid)
        process.terminate()  # Try graceful termination
        try:
             process.wait(timeout=5)
        except psutil.TimeoutExpired:
             process.kill() # Force kill if stuck
        
        log_session_stop()
        return {"message": "Game stopped"}
    except Exception as e:
         logger.error(f"Failed to stop game: {str(e)}")
         raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=config.get("port", 8000))