"""
FastAPI server for LLM-Native Framework
提供REST API接口用于Web界面和外部集成
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn
from pathlib import Path

from core.config import Config
from core.orchestrator import Orchestrator
from loguru import logger


# Pydantic models for API requests/responses
class DetectorGenerationRequest(BaseModel):
    vulnerability_desc: str
    target_framework: str = "clang"
    output_dir: Optional[str] = None

class DetectorGenerationResponse(BaseModel):
    success: bool
    message: str
    output_dir: Optional[str] = None
    generated_files: Optional[list] = None
    error: Optional[str] = None

class ValidationRequest(BaseModel):
    detector_path: str
    test_cases_dir: Optional[str] = None

class ValidationResponse(BaseModel):
    success: bool
    compilation_success: bool = False
    test_results: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class KnowledgeSearchRequest(BaseModel):
    query: str
    top_k: int = 5

class KnowledgeSearchResponse(BaseModel):
    success: bool
    results: Optional[list] = None
    error: Optional[str] = None

class EvaluationRequest(BaseModel):
    benchmark_name: str = "juliet_suite"
    output_dir: Optional[str] = None

class EvaluationResponse(BaseModel):
    success: bool
    metrics: Optional[Dict[str, Any]] = None
    benchmark_results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# Global variables
app = FastAPI(
    title="LLM-Native Static Analysis Framework API",
    description="REST API for automated static analysis detector generation",
    version="0.1.0"
)

config = None
orchestrator = None


@app.on_event("startup")
async def startup_event():
    """Initialize the framework on startup"""
    global config, orchestrator

    try:
        # Load configuration
        config_file = "config/config.yaml"
        if not Path(config_file).exists():
            config_file = "/app/config/config.yaml"

        config = Config.load_from_file(config_file)
        orchestrator = Orchestrator(config)

        logger.info("API server initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize API server: {e}")
        raise


# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "LLM-Native Static Analysis Framework API",
        "version": "0.1.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "framework_initialized": orchestrator is not None
    }


@app.post("/api/v1/generate", response_model=DetectorGenerationResponse)
async def generate_detector(request: DetectorGenerationRequest, background_tasks: BackgroundTasks):
    """Generate a static analysis detector"""
    try:
        if not orchestrator:
            raise HTTPException(status_code=500, detail="Framework not initialized")

        logger.info(f"API request: Generate detector for '{request.vulnerability_desc[:50]}...'")

        result = orchestrator.generate_detector(
            vulnerability_desc=request.vulnerability_desc,
            target_framework=request.target_framework,
            output_dir=request.output_dir
        )

        response = DetectorGenerationResponse(
            success=result.success,
            message="Detector generated successfully" if result.success else "Detector generation failed",
            output_dir=str(result.output_dir) if result.output_dir else None,
            generated_files=result.generated_files,
            error=result.error
        )

        return response

    except Exception as e:
        logger.error(f"Error in generate_detector API: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/validate", response_model=ValidationResponse)
async def validate_detector(request: ValidationRequest):
    """Validate a generated detector"""
    try:
        if not orchestrator:
            raise HTTPException(status_code=500, detail="Framework not initialized")

        logger.info(f"API request: Validate detector at '{request.detector_path}'")

        result = orchestrator.validate_detector(
            detector_path=request.detector_path,
            test_cases_dir=request.test_cases_dir
        )

        response = ValidationResponse(
            success=result.success,
            compilation_success=result.compilation_success,
            test_results=result.test_results,
            metrics=result.metrics,
            error=result.error
        )

        return response

    except Exception as e:
        logger.error(f"Error in validate_detector API: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/knowledge/search", response_model=KnowledgeSearchResponse)
async def knowledge_search(request: KnowledgeSearchRequest):
    """Search the knowledge base"""
    try:
        if not orchestrator:
            raise HTTPException(status_code=500, detail="Framework not initialized")

        logger.info(f"API request: Knowledge search for '{request.query}'")

        results = orchestrator.knowledge_search(
            query=request.query,
            top_k=request.top_k
        )

        # Convert results to dict format
        formatted_results = []
        for result in results:
            formatted_results.append({
                "title": result.title,
                "content": result.content,
                "score": result.score,
                "metadata": result.metadata
            })

        response = KnowledgeSearchResponse(
            success=True,
            results=formatted_results
        )

        return response

    except Exception as e:
        logger.error(f"Error in knowledge_search API: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/evaluate", response_model=EvaluationResponse)
async def evaluate_framework(request: EvaluationRequest, background_tasks: BackgroundTasks):
    """Evaluate framework performance"""
    try:
        if not orchestrator:
            raise HTTPException(status_code=500, detail="Framework not initialized")

        logger.info(f"API request: Evaluate framework on '{request.benchmark_name}'")

        result = orchestrator.evaluate_framework(
            benchmark_name=request.benchmark_name,
            output_dir=request.output_dir
        )

        response = EvaluationResponse(
            success=result.success,
            metrics=result.metrics,
            benchmark_results=result.benchmark_results,
            error=result.error
        )

        return response

    except Exception as e:
        logger.error(f"Error in evaluate_framework API: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/config")
async def get_config():
    """Get current configuration (without sensitive data)"""
    if not config:
        raise HTTPException(status_code=500, detail="Configuration not loaded")

    # Return config without sensitive information
    safe_config = config.get_all()
    if "llm" in safe_config and "keys_file" in safe_config["llm"]:
        safe_config["llm"]["keys_file"] = "[REDACTED]"

    return safe_config


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
