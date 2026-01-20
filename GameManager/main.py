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

@app.get("/version")
def get_version():
    """Returns the 'version' of the game (currently the directory name)."""
    if not GAME_DIRECTORY or not os.path.exists(GAME_DIRECTORY):
        return {"version": "Unknown", "status": "Directory Not Found"}
    return {"version": os.path.basename(os.path.normpath(GAME_DIRECTORY)), "status": "Installed"}

@app.post("/upload")
async def upload_game(file: UploadFile = File(...)):
    """Receives a zip file, extracts it, and replaces the game files."""
    try:
        # Stop game if running
        stop_game()
        
        zip_path = "uploaded_game.zip"
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Verify it is a zip
        if not zipfile.is_zipfile(zip_path):
             raise HTTPException(status_code=400, detail="Uploaded file is not a valid zip archive.")

        # Wipe existing directory (Backup logic can be added here)
        if os.path.exists(GAME_DIRECTORY):
            logger.info(f"Removing existing directory: {GAME_DIRECTORY}")
            shutil.rmtree(GAME_DIRECTORY)
        
        os.makedirs(GAME_DIRECTORY, exist_ok=True)

        logger.info(f"Extracting to {GAME_DIRECTORY}...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(GAME_DIRECTORY)
        
        os.remove(zip_path)
        logger.info("Upload and extraction successful.")
        
        return {"message": "Game uploaded and extracted successfully"}
    except Exception as e:
        logger.error(f"Upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/start")
def start_game():
    """Starts the game executable."""
    pid = get_process_id()
    if pid:
         return {"message": "Game is already running", "pid": pid}
    
    if not os.path.exists(GAME_EXECUTABLE):
        raise HTTPException(status_code=404, detail="Game executable not found.")

    try:
        # Use subprocess.Popen to start non-blocking
        subprocess.Popen([GAME_EXECUTABLE])
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
        return {"message": "Game stopped"}
    except Exception as e:
         logger.error(f"Failed to stop game: {str(e)}")
         raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=config.get("port", 8000))
