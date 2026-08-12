# Network Security Policy Analyzer

A full-stack security analysis tool for identifying misconfigurations, overly permissive rules, conflicts, and compliance violations in firewall rules, security groups, and IAM policies.

## Features

- **Policy Upload & Parsing:** Support AWS Security Groups, GCP Firewall rules, and generic YAML/JSON formats
- **Automated Analysis:** Detect permissiveness (0.0.0.0/0), conflicts, redundancy, and compliance violations
- **Risk Scoring:** Multi-dimensional severity assessment (permissiveness, exposure, compliance)
- **Interactive Dashboard:** Results table, network visualization, compliance charts
- **Compliance Frameworks:** Built-in CIS Benchmarks, HIPAA, PCI-DSS; extensible for custom rules
- **Actionable Recommendations:** Specific suggestions for fixing each issue
- **Real-time Progress:** WebSocket updates during analysis of large policy sets

## Tech Stack

**Backend:** Node.js + Express + TypeScript  
**Analysis Engine:** Python + FastAPI  
**Frontend:** React 18 + TypeScript + Tailwind CSS + Cytoscape.js  
**Database:** MongoDB  
**Infrastructure:** Docker + Docker Compose  

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (if running locally)
- Python 3.9+ (if running locally)
- MongoDB 5.0+ (or use Docker)

### Running with Docker Compose

```bash
git clone https://github.com/AurkoDatta/network-security-policy-analyzer.git
cd network-security-policy-analyzer

# Copy environment template
cp .env.example .env

# Start all services
docker-compose up --build

# App will be available at http://localhost:3000
```

### Local Development

**Setup Python analyzer:**
```bash
cd analyzer
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest  # Run tests
python -m uvicorn main:app --reload
```

**Setup Node.js API:**
```bash
cd api
npm install
npm run dev  # Starts on port 5000
```

**Setup React frontend:**
```bash
cd frontend
npm install
npm run dev  # Starts on port 3000
```

## Usage

1. **Upload a Policy File**
   - Click "Upload Policy" on the dashboard
   - Select a JSON (AWS) or YAML (firewall) file
   - Supported formats:
     - AWS Security Group exports (JSON)
     - Generic firewall rules (YAML/JSON)
     - IAM policy definitions (JSON)

2. **View Analysis Results**
   - Results appear in a sortable table
   - Each finding shows: severity, type, affected rule, recommendation
   - Click a finding to see full details

3. **Explore Network Diagram**
   - Interactive visualization of traffic flows
   - Hover over edges to see rule details
   - Toggle rule filters (show only critical, etc.)

4. **Check Compliance**
   - Compliance breakdown chart shows pass/fail by framework
   - Detailed compliance violations listed with fix suggestions

5. **Export Report**
   - Generate a PDF report with all findings
   - Export data as JSON for external tools

## Project Structure

```
network-security-policy-analyzer/
├── api/                        # Node.js/Express API gateway
│   ├── src/
│   │   ├── routes/
│   │   ├── middleware/
│   │   ├── models/            # Mongoose schemas
│   │   └── controllers/
│   ├── tests/
│   ├── package.json
│   └── tsconfig.json
├── analyzer/                   # Python/FastAPI analysis engine
│   ├── src/
│   │   ├── parsers/           # Rule parsers
│   │   ├── detectors/         # Analysis algorithms
│   │   ├── compliance/        # Compliance rule matching
│   │   ├── models.py          # Data models
│   │   └── main.py            # FastAPI app
│   ├── tests/
│   ├── requirements.txt
│   └── pytest.ini
├── frontend/                   # React/TypeScript UI
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── services/          # API client
│   │   └── App.tsx
│   ├── tests/
│   ├── package.json
│   └── vite.config.ts
├── docs/                       # Documentation
│   ├── architecture.md
│   ├── api.md
│   └── user-guide.md
├── docker-compose.yml
├── .env.example
├── LICENSE
└── README.md
```

## API Endpoints

### Policies
- `POST /api/policies/upload` - Upload a policy file
- `GET /api/policies` - List user's policies
- `GET /api/policies/:id` - Get policy details
- `DELETE /api/policies/:id` - Delete a policy

### Analysis
- `POST /api/policies/:id/analyze` - Trigger analysis
- `WS /ws/analyze/:id` - Real-time progress updates
- `GET /api/analyses/:id` - Get analysis results
- `GET /api/analyses/:id/report` - Generate PDF report

### Compliance
- `GET /api/compliance-rules` - List compliance frameworks
- `POST /api/compliance-rules` - Create custom rule

See `/docs/api.md` for detailed endpoint documentation.

## Testing

Run tests for each service:

```bash
# Python analyzer tests
cd analyzer
pytest -v --cov=src

# Node.js API tests
cd api
npm test

# React component tests
cd frontend
npm test
```

Target coverage: Python 85%, Node.js 75%, React 60%.

## Configuration

Customize behavior via `.env` file:

```env
# MongoDB
MONGODB_URI=mongodb://localhost:27017/analyzer

# Ports
API_PORT=5000
ANALYZER_PORT=8000
FRONTEND_PORT=3000

# JWT
JWT_SECRET=your-secret-key-here

# Max file upload size (bytes)
MAX_FILE_SIZE=10485760

# Analysis timeout (seconds)
ANALYSIS_TIMEOUT=30
```

## Architecture

See `docs/architecture.md` for detailed system design, including:
- Microservice decomposition
- Database schema
- Analysis algorithms
- Compliance framework
- Design decisions

## Compliance Frameworks

Built-in support for:
- **CIS Benchmarks** - Security baselines for AWS, GCP, etc.
- **HIPAA** - Healthcare security requirements
- **PCI-DSS** - Payment card industry standards
- **Custom Rules** - Define your own compliance checks in JSON

## Contributing

This is a personal project, but follow these guidelines:

1. **Branches:** Feature branches off `main` (e.g., `feat/custom-rules`)
2. **Commits:** Use conventional commit format (see prompt.txt)
3. **Tests:** All new code must include tests (75%+ coverage)
4. **Docs:** Update relevant docs when adding features
5. **Code Style:** Run formatters and linters before committing

## Performance

- Analyzes 100 rules in <1 second
- Analyzes 500 rules in <3 seconds
- Analyzes 1000+ rules in <5 seconds
- API responses average <200ms
- Database queries optimized with indexes

## License

MIT License - See LICENSE file for details.

## Future Roadmap

- [ ] Multi-cloud support (AWS, GCP, Azure, Kubernetes)
- [ ] Network flow log integration (detect unused rules)
- [ ] Change tracking and drift detection
- [ ] Auto-remediation (generate Terraform/CloudFormation)
- [ ] Scheduled policy scanning and alerts
- [ ] Advanced ML-based anomaly detection
- [ ] Team collaboration and policy reviews

## Support & Questions

For issues, questions, or suggestions, open an issue on GitHub.

---

**Getting Started Development:** See `docs/architecture.md` for system design details.
