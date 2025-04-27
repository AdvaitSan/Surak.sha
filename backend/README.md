# Flask Backend Setup with UV

This guide will help you set up the Flask backend using `uv`, a fast Python package installer and resolver.

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

### 1. Install UV

First, install `uv` using pip:

```bash
pip install uv
```

### 2. Create Virtual Environment

Create a new virtual environment using `uv`:

```bash
uv venv
```

This will create a `.venv` directory in your project.

### 3. Activate Virtual Environment

- **Windows**:
```bash
.venv\Scripts\activate
```

- **Unix/MacOS**:
```bash
source .venv/bin/activate
```

### 4. Install Dependencies

Install all project dependencies using `uv`:

```bash
uv pip install -r requirements.txt
```

## Common UV Commands

### Installing Packages

```bash
# Install a single package
uv pip install package-name

# Install with specific version
uv pip install package-name==1.0.0

# Install from requirements file
uv pip install -r requirements.txt
```

### Managing Dependencies

```bash
# Generate a locked requirements file
uv pip compile requirements.txt -o requirements.lock

# Install from locked requirements file
uv pip sync requirements.lock

# Update all packages
uv pip install --upgrade -r requirements.txt
```

### Virtual Environment

```bash
# Create a new virtual environment
uv venv

# Create with specific Python version
uv venv --python 3.9
```

## Project Structure

```
backend/
├── app.py                 # Main application file
├── config.py             # Configuration settings
├── .env                  # Environment variables
├── .gitignore           # Git ignore file
├── requirements.txt     # Project dependencies
├── routes/              # Route blueprints
│   ├── __init__.py
│   └── routes.py
├── services/            # Business logic
│   ├── __init__.py
│   └── sample_service.py
└── utils/               # Utility functions
    ├── __init__.py
    └── helpers.py
```

## Running the Application

1. Make sure your virtual environment is activated
2. Set up your environment variables in `.env`
3. Run the Flask application:

```bash
python app.py
```

## Troubleshooting

### Common Issues

1. **UV not found**
   - Make sure `uv` is installed: `pip install uv`
   - Check if it's in your PATH

2. **Virtual Environment Issues**
   - If activation fails, try creating a new environment: `uv venv`
   - Make sure you're in the correct directory

3. **Dependency Installation Issues**
   - Try clearing the cache: `uv pip cache purge`
   - Check your internet connection
   - Verify Python version compatibility

### Getting Help

- UV Documentation: https://github.com/astral-sh/uv
- Flask Documentation: https://flask.palletsprojects.com/
- Python Virtual Environments: https://docs.python.org/3/tutorial/venv.html

## Best Practices

1. Always use a virtual environment
2. Keep your requirements.txt up to date
3. Use `uv pip compile` to generate locked requirements
4. Commit both requirements.txt and requirements.lock to version control
5. Regularly update dependencies using `uv pip install --upgrade`

## Contributing

1. Create a new virtual environment
2. Install dependencies
3. Make your changes
4. Test your changes
5. Submit a pull request 