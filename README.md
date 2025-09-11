# Secure AI Data Pipeline Platform

A comprehensive cloud security analysis platform that ingests multi-cloud resource data, analyzes security risks using AI and graph neural networks, and provides actionable remediation recommendations.

## 🚀 Features

### Core Capabilities

- **Multi-Cloud Data Ingestion**: Automated data collection from AWS, GCP, and Azure using CloudQuery
- **AI-Powered Security Analysis**: Advanced threat detection using OpenAI GPT-4 and secure prompt templates
- **Graph Neural Network Analysis**: Relationship detection and attack path analysis using NetworkX
- **Data Sanitization Pipeline**: PII removal and differential privacy for secure AI processing
- **Automated Remediation**: Infrastructure-as-Code generation for security fixes
- **Interactive Dashboard**: Modern React/Next.js interface with real-time visualizations

### Security Features

- **Risk Scoring**: 0-10 risk assessment with contextual analysis
- **Attack Path Detection**: Privilege escalation and lateral movement analysis
- **Compliance Monitoring**: PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR support
- **Data Exfiltration Detection**: Cross-cloud and cross-region risk analysis
- **Network Segmentation Analysis**: Violation detection and remediation
- **Insider Threat Detection**: Overprivileged access and anomaly detection

## 🏗️ Architecture

### High-Level System Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CloudQuery    │───▶│   PostgreSQL    │◀───│   FastAPI       │
│   Data Sync     │    │   Database      │    │   Backend       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐             │
│   AI Analysis   │◀───│  Data Sanitizer │◀────────────┤
│   Engine        │    │   Pipeline      │             │
└─────────────────┘    └─────────────────┘             │
                                                        │
┌─────────────────┐    ┌─────────────────┐             │
│ Graph Analysis  │◀───│  Risk Detection │◀────────────┤
│    Engine       │    │    Engine       │             │
└─────────────────┘    └─────────────────┘             │
                                                        │
┌─────────────────┐    ┌─────────────────┐             │
│  Remediation    │◀───│   Next.js       │◀────────────┘
│    Engine       │    │   Dashboard     │
└─────────────────┘    └─────────────────┘
```

### Detailed Data Pipeline Flow

The Secure AI Data Pipeline processes cloud security data through eight critical stages, each with comprehensive security measures:

#### Stage 1: Data Collection & Ingestion

- **CloudQuery** connects to AWS, GCP, and Azure using encrypted credentials
- **Multi-cloud sync** runs on schedule, collecting raw resource data
- **Data normalization** standardizes different cloud provider formats
- **Security**: Read-only access, encrypted connections, audit logging

#### Stage 2: Data Storage & Normalization  

- **PostgreSQL** receives normalized cloud resource data
- **Resource relationships** automatically detected and stored
- **Metadata extraction** captures security attributes (public access, encryption)
- **Security**: Database encryption at rest, access controls, data integrity constraints

#### Stage 3: Data Sanitization Pipeline

- **PII detection** scans for personally identifiable information
- **Sensitive data masking** replaces sensitive values with masked versions
- **Identifier hashing** anonymizes cloud resource IDs while preserving structure
- **Differential privacy** adds statistical noise to numeric data
- **Security**: PII removal, identifier anonymization, data masking

#### Stage 4: AI-Powered Security Analysis

- **Sanitized data** sent to OpenAI GPT-4 for contextual analysis
- **Secure prompt templates** ensure consistent, secure AI interactions
- **Risk scoring** generates 0-10 risk assessments
- **Compliance checking** evaluates against PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR
- **Security**: Prompt injection protection, data anonymization, output validation

#### Stage 5: Graph Neural Network Analysis

- **Resource graph construction** builds NetworkX graphs from relationships
- **Attack path detection** identifies privilege escalation routes
- **Centrality analysis** calculates resource importance scores
- **Vulnerability clustering** groups related security risks
- **Security**: Graph-based analysis, attack path scoring, anomaly detection

#### Stage 6: Risk Detection Engine

- **Multi-cloud risk analysis** identifies risks spanning multiple providers
- **Compliance violation detection** checks against regulatory frameworks
- **Insider threat detection** identifies overprivileged accounts
- **Network segmentation analysis** detects boundary violations
- **Security**: Cross-cloud risk detection, compliance mapping, risk prioritization

#### Stage 7: Automated Remediation

- **Terraform code generation** creates Infrastructure-as-Code fixes
- **Manual procedure generation** provides step-by-step remediation guides
- **Rollback planning** creates safety procedures for infrastructure changes
- **Validation steps** define post-remediation verification procedures
- **Security**: Automated fixes, rollback procedures, validation workflows

#### Stage 8: Dashboard & Visualization

- **Real-time dashboard** displays security metrics and findings
- **Interactive graphs** show resource relationships and attack paths
- **Compliance reporting** provides framework-specific violation tracking
- **Remediation tracking** monitors fix progress and effectiveness
- **Security**: JWT authentication, role-based access, data filtering

### Data Flow Summary

```text
Raw Cloud Data → CloudQuery Collection → PostgreSQL Storage → Data Sanitization → 
AI Analysis → Graph Analysis → Risk Detection → Remediation Generation → 
Dashboard Visualization
```

Each stage adds security layers and processing capabilities, ensuring sensitive data protection while providing comprehensive security insights and automated remediation capabilities.

### Key Components and Interactions

#### CloudQuery Integration

- **Multi-cloud Support**: Unified data collection from AWS, GCP, and Azure
- **Real-time Sync**: Continuous monitoring of cloud resource changes
- **Schema Normalization**: Standardized data models across cloud providers
- **Relationship Discovery**: Automatic detection of resource dependencies

#### Data Processing Engine

- **Sanitization Pipeline**: Multi-stage PII removal and data anonymization
- **AI Analysis Engine**: GPT-4 powered contextual security assessment
- **Graph Analysis**: NetworkX-based relationship and attack path analysis
- **Risk Detection**: Multi-cloud risk assessment and compliance checking

#### Remediation System

- **Terraform Generation**: Automated Infrastructure-as-Code fix generation
- **Manual Procedures**: Step-by-step remediation guides for complex issues
- **Rollback Planning**: Safety procedures for infrastructure changes
- **Validation Workflows**: Post-remediation verification and testing

#### Dashboard and Visualization

- **Real-time Metrics**: Live security posture and risk scoring
- **Interactive Graphs**: Visual representation of resource relationships
- **Compliance Reporting**: Framework-specific violation tracking
- **Remediation Tracking**: Progress monitoring and effectiveness measurement

## 🛠️ Tech Stack

### Backend

- **Framework**: FastAPI with Python 3.11+
- **Database**: PostgreSQL 15+ with JSONB support
- **ORM**: SQLAlchemy 2.0
- **Authentication**: JWT with bcrypt hashing
- **AI/ML**: OpenAI GPT-4, NetworkX, scikit-learn
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
- **Graph Analysis**: NetworkX (in-memory graph processing)
- **Caching**: Redis

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
# Run initial CloudQuery sync
docker-compose run --rm cloudquery sync /configs/aws.yml
docker-compose run --rm cloudquery sync /configs/gcp.yml
docker-compose run --rm cloudquery sync /configs/azure.yml
```

### 5. Access the Dashboard

- **Frontend**: <http://localhost:3000>
- **API Documentation**: <http://localhost:8000/docs>
- **Grafana**: <http://localhost:3001> (admin/admin)

## 📊 Usage

### Dashboard Overview

The main dashboard provides:

- **Security Overview**: Risk metrics and finding distribution
- **Resource Inventory**: Multi-cloud resource tracking
- **Network Graph**: Interactive visualization of resource relationships
- **Compliance Status**: Framework-specific violation tracking

### Security Analysis

1. **Automated Scanning**: Resources are continuously analyzed for security risks
2. **AI Analysis**: GPT-4 powered contextual security assessment
3. **Risk Scoring**: 0-10 scale with severity classification
4. **Attack Paths**: Graph-based privilege escalation detection

### Remediation

1. **Auto-Generated Fixes**: Terraform code for common security issues
2. **Manual Procedures**: Step-by-step remediation guides
3. **Rollback Plans**: Safety procedures for infrastructure changes
4. **Validation Steps**: Post-remediation verification

## 🔒 Security Considerations

### Comprehensive Security Architecture

The platform implements defense-in-depth security across all pipeline stages:

#### Data Protection Layers

- **Encryption at Rest**: All sensitive data encrypted using AES-256 encryption
- **Encryption in Transit**: TLS 1.3 for all network communications
- **PII Sanitization**: Automatic detection and removal of emails, SSNs, credit cards, phone numbers
- **Differential Privacy**: Laplace noise added to numeric data to prevent inference attacks
- **Access Controls**: JWT-based authentication with role-based permissions and token expiration

#### AI Security Measures

- **Prompt Injection Protection**: Secure templates prevent malicious prompt injection attacks
- **Data Anonymization**: Cloud resource identifiers are hashed with salt before AI analysis
- **Output Validation**: AI responses are validated and sanitized before processing
- **Audit Logging**: Complete trail of all AI interactions for compliance and debugging
- **Rate Limiting**: API rate limits prevent abuse and ensure fair usage

#### Infrastructure Security

- **Container Security**: Non-root users, minimal base images, security scanning
- **Network Security**: Internal service communication, security headers, network isolation
- **Secret Management**: Environment-based secret injection, no hardcoded credentials
- **Monitoring**: Comprehensive logging, metrics collection, and alerting
- **Vulnerability Management**: Regular security updates and dependency scanning

#### Compliance Features

- **PCI DSS**: Payment card data protection and encryption requirements
- **SOC 2**: Security, availability, and confidentiality controls
- **ISO 27001**: Information security management standards
- **HIPAA**: Healthcare data protection requirements
- **GDPR**: European data protection and privacy regulations

### Pipeline-Specific Security

#### Data Collection Security

- **Read-only Access**: CloudQuery uses read-only IAM roles to minimize risk
- **Credential Encryption**: Cloud provider credentials encrypted at rest using Fernet
- **Network Isolation**: Data collection through secure, encrypted connections
- **Audit Logging**: All data collection activities logged with timestamps

#### Data Processing Security

- **Input Validation**: All data inputs validated and sanitized
- **SQL Injection Prevention**: Parameterized queries and ORM protection
- **Cross-Site Scripting (XSS) Prevention**: Output encoding and CSP headers
- **Data Integrity**: Foreign key constraints and validation rules

#### AI Processing Security

- **Secure Prompt Templates**: Pre-defined templates prevent injection attacks
- **Data Minimization**: Only necessary data sent to AI services
- **Response Sanitization**: AI outputs validated before storage
- **Privacy Preservation**: Sensitive data never leaves the secure environment

#### Remediation Security

- **Code Validation**: Generated Terraform code validated for security
- **Rollback Procedures**: Safe recovery mechanisms for failed remediations
- **Access Controls**: Remediation actions require appropriate permissions
- **Audit Trails**: All remediation actions logged and tracked

## 📈 Monitoring and Observability

### Metrics

- **Application Metrics**: Request latency, error rates, throughput
- **Security Metrics**: Finding counts, risk scores, remediation rates
- **Infrastructure Metrics**: Resource utilization, database performance
- **Business Metrics**: Compliance scores, coverage percentages

### Logging

- **Structured Logging**: JSON format with correlation IDs
- **Security Events**: Authentication, authorization, data access
- **Audit Trail**: All security findings and remediation actions
- **Error Tracking**: Comprehensive error reporting and alerting

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

### Testing

```bash
# Backend tests
cd backend
pytest tests/

# Frontend tests
cd frontend
npm test
```

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

### Development Guidelines

- Follow PEP 8 for Python code
- Use TypeScript for all new frontend code
- Add tests for new features
- Update documentation for API changes
- Use conventional commit messages

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation

- [API Reference](docs/api.md)
- [Configuration Guide](docs/configuration.md)
- [Security Best Practices](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

### Community

- [GitHub Issues](https://github.com/your-org/secure-ai-data-pipelines/issues)
- [Discussions](https://github.com/your-org/secure-ai-data-pipelines/discussions)
- [Security Advisories](https://github.com/your-org/secure-ai-data-pipelines/security/advisories)

### Commercial Support

For enterprise support, training, and custom development, contact [support@yourcompany.com](mailto:support@yourcompany.com).

## 🙏 Acknowledgments

- [CloudQuery](https://www.cloudquery.io/) for multi-cloud data ingestion
- [OpenAI](https://openai.com/) for AI-powered security analysis
- [NetworkX](https://networkx.org/) for graph analysis capabilities
- [FastAPI](https://fastapi.tiangolo.com/) for the robust API framework
- [Next.js](https://nextjs.org/) for the modern frontend framework

---

## Built with ❤️ for cloud security professionals
