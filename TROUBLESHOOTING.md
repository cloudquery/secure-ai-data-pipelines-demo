# Troubleshooting Guide

This guide covers common issues and their solutions for the Secure AI Data Pipeline Platform.

## Data Processing Issues

### Workers Not Processing Data

```bash
# Check if workers are running
docker-compose ps data-processor

# Check worker logs
docker-compose logs data-processor

# Restart workers
docker-compose restart data-processor

# Check database notifications
docker-compose exec postgres psql -U cloudquery -d cloudquery_security -c "
SELECT * FROM sync_processing_queue ORDER BY created_at DESC LIMIT 10;
"
```

### CloudQuery Sync Issues

```bash
# Check CloudQuery logs
docker-compose logs cloudquery

# Test CloudQuery connection
docker-compose run --rm cloudquery sync --dry-run /configs/aws.yml

# Verify credentials
docker-compose exec cloudquery env | grep -E "(AWS|GCP|AZURE)"
```

### Database Connection Issues

```bash
# Check database status
docker-compose exec postgres pg_isready -U cloudquery

# Test database connection
docker-compose exec backend python -c "
from app.models.database import engine
print('Database connection:', engine.connect())
"

# Reset database (WARNING: This will delete all data)
docker-compose down -v
docker-compose up -d postgres
```

## Common Issues

### Service Startup Problems

If services fail to start:

```bash
# Check all service status
docker-compose ps

# View detailed logs
docker-compose logs

# Restart specific service
docker-compose restart <service-name>

# Rebuild and restart
docker-compose up -d --build
```

### Environment Configuration Issues

Verify your `.env` file contains all required variables:

```bash
# Check environment variables
docker-compose exec backend env | grep -E "(DATABASE|OPENAI|AWS|GCP|AZURE|SECRET)"
```

### Network Connectivity Issues

```bash
# Test internal network connectivity
docker-compose exec backend ping postgres
docker-compose exec backend ping redis

# Check port bindings
docker-compose port backend 8000
docker-compose port frontend 3000
```

### Data Processing Failures

```bash
# Check processing queue
docker-compose exec postgres psql -U cloudquery -d cloudquery_security -c "
SELECT COUNT(*) FROM sync_processing_queue WHERE status = 'pending';
"

# Manual data processing test
docker-compose run --rm data-processor python -c "
from app.workers.simple_data_processor import SimpleDataProcessor
processor = SimpleDataProcessor()
print('Data processor test successful')
"
```

## Performance Issues

### High Memory Usage

```bash
# Check container resource usage
docker stats

# Restart services to free memory
docker-compose restart

# Scale workers if needed
docker-compose up -d --scale data-processor=2
```

### Slow Database Queries

```bash
# Check database performance
docker-compose exec postgres psql -U cloudquery -d cloudquery_security -c "
SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;
"
```

## Getting Help

If you encounter issues not covered in this guide:

1. Check the application logs: `docker-compose logs -f`
2. Verify your environment configuration
3. Ensure all prerequisites are met
4. Check the [main README](README.md) for setup instructions
5. Review the API documentation at `http://localhost:8000/docs`
