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

## 🏗️ Architecture

The platform processes cloud security data through an automated pipeline:

```text
CloudQuery Sync → PostgreSQL → Background Workers → AI Analysis → Dashboard
```

Key components include CloudQuery for multi-cloud data collection, PostgreSQL for storage, background workers for processing, AI analysis for security assessment, and a React dashboard for visualization.

## 🛠️ Troubleshooting

For detailed troubleshooting information, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Built with ❤️ by CloudQuery
