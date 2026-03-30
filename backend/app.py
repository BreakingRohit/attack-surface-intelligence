"""
FastAPI backend for Attack Surface Intelligence System
Provides REST API for reconnaissance scanning with custom wordlist support
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pathlib import Path
import os
import json
import uuid
from typing import Optional, Dict, Any
import asyncio
from datetime import datetime

# Import the main reconnaissance class
import sys
sys.path.insert(0, str(Path(__file__).parent))

from modules.main import AttackSurfaceIntelligence

# Create FastAPI app
app = FastAPI(
    title="Attack Surface Intelligence System API",
    description="Professional reconnaissance and vulnerability assessment framework",
    version="2.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create wordlists directory
WORDLISTS_DIR = Path(__file__).parent / "wordlists"
WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)

# Create a directory for uploads
UPLOADS_DIR = WORDLISTS_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# Store scan results
SCANS_DIR = Path(__file__).parent / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)

# In-memory scan status
scan_status: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    """Request model for starting a scan"""
    target: str
    subdomain_wordlist: str = "default"  # "default" or filename
    directory_wordlist: str = "default"  # "default" or filename
    threads: int = 25
    timeout: int = 4
    verbose: bool = False


class WordlistResponse(BaseModel):
    """Response model for wordlist upload"""
    filename: str
    status: str
    size: int
    entries: int


class ScanResponse(BaseModel):
    """Response model for scan initiation"""
    scan_id: str
    status: str
    target: str
    message: str


class ScanStatusResponse(BaseModel):
    """Response model for scan status"""
    scan_id: str
    status: str  # "pending", "running", "completed", "failed"
    target: str
    progress: Optional[str] = None
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Attack Surface Intelligence System API",
        "version": "2.0"
    }


@app.post("/upload-wordlist", response_model=WordlistResponse)
async def upload_wordlist(file: UploadFile = File(...)):
    """
    Upload a custom wordlist file
    
    Accepts: .txt files only
    Returns: filename, status, size, and entry count
    """
    
    # Validate file type
    if not file.filename.endswith('.txt'):
        raise HTTPException(status_code=400, detail="Only .txt files are allowed")
    
    # Read file content
    content = await file.read()
    
    # Validate file size (max 10MB)
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")
    
    # Decode and parse wordlist
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")
    
    # Process wordlist: remove duplicates, empty lines, trim whitespace
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    unique_lines = list(set(lines))  # Remove duplicates
    
    # Validate wordlist size (max 10,000 entries)
    if len(unique_lines) > 10000:
        raise HTTPException(
            status_code=400,
            detail=f"Wordlist too large ({len(unique_lines)} entries, max 10,000)"
        )
    
    # Generate safe filename
    safe_filename = f"wordlist_{uuid.uuid4().hex}_{file.filename}"
    filepath = UPLOADS_DIR / safe_filename
    
    # Save the cleaned wordlist
    cleaned_content = '\n'.join(unique_lines)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(cleaned_content)
    
    return WordlistResponse(
        filename=safe_filename,
        status="uploaded",
        size=len(cleaned_content),
        entries=len(unique_lines)
    )


@app.get("/wordlists")
async def list_wordlists():
    """List all uploaded wordlists"""
    try:
        files = list(UPLOADS_DIR.glob("wordlist_*.txt"))
        return {
            "status": "success",
            "wordlists": [f.name for f in files],
            "default_available": True
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a reconnaissance scan
    
    Accepts:
    - target: domain to scan
    - subdomain_wordlist: "default" or uploaded filename
    - directory_wordlist: "default" or uploaded filename
    
    Returns: scan_id for tracking progress
    """
    
    # Validate target
    if not request.target:
        raise HTTPException(status_code=400, detail="Target domain is required")
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Resolve wordlist paths
    sub_wordlist = None
    if request.subdomain_wordlist != "default":
        sub_wordlist = UPLOADS_DIR / request.subdomain_wordlist
        if not sub_wordlist.exists():
            raise HTTPException(status_code=404, detail="Subdomain wordlist not found")
    
    dir_wordlist = None
    if request.directory_wordlist != "default":
        dir_wordlist = UPLOADS_DIR / request.directory_wordlist
        if not dir_wordlist.exists():
            raise HTTPException(status_code=404, detail="Directory wordlist not found")
    
    # Initialize scan status
    scan_status[scan_id] = {
        "status": "pending",
        "target": request.target,
        "started_at": datetime.now().isoformat(),
        "progress": "Initializing scan...",
        "results": None,
        "error": None
    }
    
    # Schedule scan in background
    background_tasks.add_task(
        run_scan,
        scan_id=scan_id,
        target=request.target,
        sub_wordlist=sub_wordlist,
        dir_wordlist=dir_wordlist,
        threads=request.threads,
        timeout=request.timeout,
        verbose=request.verbose
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        target=request.target,
        message="Scan initiated. Use scan_id to check progress."
    )


@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get the status of a scan"""
    
    if scan_id not in scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status_info = scan_status[scan_id]
    
    return ScanStatusResponse(
        scan_id=scan_id,
        status=status_info["status"],
        target=status_info["target"],
        progress=status_info.get("progress"),
        results=status_info.get("results"),
        error=status_info.get("error")
    )


@app.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the full results of a completed scan"""
    
    if scan_id not in scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status_info = scan_status[scan_id]
    
    if status_info["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")
    
    return status_info.get("results", {})


async def run_scan(
    scan_id: str,
    target: str,
    sub_wordlist: Optional[Path],
    dir_wordlist: Optional[Path],
    threads: int,
    timeout: int,
    verbose: bool
):
    """
    Run the reconnaissance scan
    """
    try:
        # Update status
        scan_status[scan_id]["status"] = "running"
        scan_status[scan_id]["progress"] = "Starting reconnaissance..."
        
        # Convert Path objects to strings
        sub_wordlist_str = str(sub_wordlist) if sub_wordlist else None
        dir_wordlist_str = str(dir_wordlist) if dir_wordlist else None
        
        # Initialize the reconnaissance engine
        asi = AttackSurfaceIntelligence(
            target=target,
            threads=threads,
            timeout=timeout,
            verbose=verbose,
            sub_wordlist=sub_wordlist_str,
            dir_wordlist=dir_wordlist_str
        )
        
        # Run the scan
        results = asi.run_reconnaissance()
        
        # Convert sets to lists for JSON serialization
        results['subdomains'] = list(results.get('subdomains', set()))
        results['alive_subdomains'] = list(results.get('alive_subdomains', set()))
        results['urls'] = list(results.get('urls', set()))
        results['alive_endpoints'] = {
            k: list(v) if isinstance(v, set) else v
            for k, v in results.get('alive_endpoints', {}).items()
        }
        results['endpoints'] = {
            k: list(v) if isinstance(v, set) else v
            for k, v in results.get('endpoints', {}).items()
        }
        
        # Add wordlist info to results
        results['wordlists_used'] = {
            'subdomain': 'default' if sub_wordlist_str is None else sub_wordlist_str,
            'directory': 'default' if dir_wordlist_str is None else dir_wordlist_str
        }
        
        # Store results
        scan_status[scan_id]["status"] = "completed"
        scan_status[scan_id]["results"] = results
        scan_status[scan_id]["completed_at"] = datetime.now().isoformat()
        
        # Save to file
        results_file = SCANS_DIR / f"{scan_id}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
    except Exception as e:
        scan_status[scan_id]["status"] = "failed"
        scan_status[scan_id]["error"] = str(e)
        print(f"[ERROR] Scan {scan_id} failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
