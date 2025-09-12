# Secure AI Data Pipeline Platform

A comprehensive cloud security analysis platform that ingests multi-cloud resource data and analyzes security risks using AI-powered threat detection.

## 🚀 Features

- **Multi-Cloud Data Ingestion**: Automated data collection from AWS, GCP, and Azure using CloudQuery
- **AI-Powered Security Analysis**: Advanced threat detection using OpenAI GPT-4 and secure prompt templates
- **Data Sanitization Pipeline**: PII removal and differential privacy for secure AI processing
- **Interactive Dashboard**: Modern React/Next.js interface
- **Risk Scoring**: 0-10 risk assessment with contextual analysis
- **Compliance Monitoring**: PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR support

## 📦 Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js 18+ (for local development)
- Python 3.11+ (for local development)
- Cloud provider credentials (AWS, GCP, Azure)

### 1. Clone and Setup

```bash
git clone <repository-url>
cd secure-ai-data-pipelines

# Copy environment configuration
cp env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Configure Environment

Update `.env` with your settings:

```bash
# Database
DATABASE_URL=postgresql://cloudquery:secure_password@localhost:5432/cloudquery_security

# AI API Keys
OPENAI_API_KEY=sk-your-openai-api-key-here

# Cloud Provider Credentials
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
GCP_PROJECT_ID=your-gcp-project-id
AZURE_SUBSCRIPTION_ID=your-azure-subscription-id

# Security
SECRET_KEY=your-super-secret-jwt-key-here
ENCRYPTION_KEY=your-32-byte-encryption-key-here
```

### 3. Start the Platform

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f backend
```

### 4. Initialize Data Sync

```bash
# Run initial CloudQuery sync for each cloud provider
docker-compose run --rm cloudquery sync /configs/aws.yml
docker-compose run --rm cloudquery sync /configs/gcp.yml
docker-compose run --rm cloudquery sync /configs/azure.yml
```

### 5. Access the Dashboard

- **Frontend**: <http://localhost:3000>
- **API Documentation**: <http://localhost:8000/docs>
- **Grafana**: <http://localhost:3001> (admin/admin)

## 🏗️ Architecture

### Data Pipeline Overview

The platform processes cloud security data through an automated, event-driven pipeline:

```text
CloudQuery Sync → PostgreSQL → Event Triggers → Background Workers → 
AI Analysis → Security Detection → Dashboard
```

### Key Components

- **CloudQuery**: Multi-cloud data collection from AWS, GCP, and Azure
- **PostgreSQL**: Centralized data storage with event-driven notifications
- **Background Workers**: Automated data processing and normalization
- **AI Analysis**: GPT-4 powered security assessment and risk scoring
- **Dashboard**: Real-time visualization and compliance reporting

## 🛠️ Tech Stack

### Backend

- **Framework**: FastAPI with Python 3.11+
- **Database**: PostgreSQL 15+ with JSONB support
- **ORM**: SQLAlchemy 2.0
- **Authentication**: JWT with bcrypt hashing
- **AI/ML**: OpenAI GPT-4, scikit-learn
- **Data Processing**: CloudQuery, Pandas, NumPy

### Frontend

- **Framework**: Next.js 14 with React 18
- **Styling**: Tailwind CSS with HeadlessUI
- **Visualization**: D3.js, Recharts, React Force Graph
- **State Management**: React Query
- **Forms**: React Hook Form with Zod validation

### Infrastructure

- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose
- **Monitoring**: Prometheus + Grafana
- **Caching**: Redis

## 📊 Usage

### Dashboard Features

- **Security Overview**: Real-time risk metrics and finding distribution
- **Compliance Status**: Framework-specific violation tracking (PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR)
- **Interactive Graphs**: Visual representation of resource relationships

## 🔒 Security

### Data Protection

- **Encryption**: AES-256 at rest, TLS 1.3 in transit
- **PII Sanitization**: Automatic detection and removal of sensitive data
- **Access Controls**: JWT authentication with role-based permissions
- **Audit Logging**: Complete trail of all activities

### AI Security

- **Prompt Injection Protection**: Secure templates prevent malicious attacks
- **Data Anonymization**: Resource identifiers hashed before AI analysis
- **Output Validation**: AI responses validated and sanitized
- **Privacy Preservation**: Sensitive data never leaves secure environment

### Compliance

Supports PCI DSS, SOC 2, ISO 27001, HIPAA, and GDPR requirements with automated compliance checking and reporting.

## 📈 Monitoring

- **Metrics**: Application performance, security findings, compliance scores
- **Logging**: Structured JSON logs with correlation IDs
- **Alerting**: Real-time notifications for security events
- **Dashboards**: Grafana visualization for system health

## 🔧 Development

### Backend Development

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

### Data Processing Development

```bash
# Run data processor locally
cd backend
python app/workers/simple_data_processor.py

# Test specific data processing
python process_azure_data.py
python process_cloudquery_data.py

# Run with Docker for testing
docker-compose run --rm data-processor
```

### Testing

```bash
# Backend tests
cd backend
pytest tests/

# Frontend tests
cd frontend
npm test

# Test data processing
docker-compose run --rm data-processor python -c "
from app.workers.simple_data_processor import SimpleDataProcessor
processor = SimpleDataProcessor()
print('Data processor test successful')
"
```

## 🛠️ Troubleshooting

For detailed troubleshooting information, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 📚 API Documentation

### Core Endpoints

#### Resources

- `GET /api/v1/resources/` - List cloud resources
- `GET /api/v1/resources/{id}` - Get resource details
- `GET /api/v1/resources/stats/overview` - Resource statistics
- `POST /api/v1/resources/{id}/scan` - Trigger security scan

#### Security

- `GET /api/v1/security/findings` - List security findings
- `GET /api/v1/security/findings/{id}` - Get finding details
- `PUT /api/v1/security/findings/{id}/status` - Update finding status
- `POST /api/v1/security/analyze` - Trigger AI analysis
- `GET /api/v1/security/dashboard` - Security dashboard data

### Authentication

All API endpoints require JWT authentication:

```bash
# Get access token
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use token in requests
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/resources/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Built with ❤️ by CloudQuery
