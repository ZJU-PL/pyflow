"""
Reproducible list of public Python repositories for evaluation.

Selection criteria:
- Popular/maintained Python projects (GitHub stars > 1000)
- Diverse domains (web, data, ML, system tools, CLI, testing)
- Actively maintained (recent commits)
- Primarily Python code (not bindings-heavy)
- Mix of simple and complex codebases
"""

from dataclasses import dataclass
from typing import List


@dataclass
class RepoInfo:
    """Public repository metadata."""
    name: str
    github_url: str
    description: str
    primary_purpose: str
    stars_approx: int  # Approximate at time of listing


# Tier 1: Small to medium, well-structured projects (start here)
TIER_1_REPOS: List[RepoInfo] = [
    RepoInfo(
        name="click",
        github_url="https://github.com/pallets/click",
        description="Python composable command line interface toolkit",
        primary_purpose="CLI framework",
        stars_approx=15000,
    ),
    RepoInfo(
        name="flask",
        github_url="https://github.com/pallets/flask",
        description="Lightweight WSGI web application framework",
        primary_purpose="Web framework",
        stars_approx=67000,
    ),
    RepoInfo(
        name="requests",
        github_url="https://github.com/psf/requests",
        description="Simple HTTP library for Python",
        primary_purpose="HTTP client",
        stars_approx=52000,
    ),
    RepoInfo(
        name="pytest",
        github_url="https://github.com/pytest-dev/pytest",
        description="Testing framework",
        primary_purpose="Testing",
        stars_approx=11000,
    ),
    RepoInfo(
        name="rich",
        github_url="https://github.com/Textualize/rich",
        description="Rich text and beautiful formatting in the terminal",
        primary_purpose="Terminal UI",
        stars_approx=49000,
    ),
]

# Tier 2: Larger, more complex projects
TIER_2_REPOS: List[RepoInfo] = [
    RepoInfo(
        name="django",
        github_url="https://github.com/django/django",
        description="High-level Python web framework",
        primary_purpose="Web framework",
        stars_approx=79000,
    ),
    RepoInfo(
        name="scikit-learn",
        github_url="https://github.com/scikit-learn/scikit-learn",
        description="Machine learning library",
        primary_purpose="ML",
        stars_approx=59000,
    ),
    RepoInfo(
        name="ansible",
        github_url="https://github.com/ansible/ansible",
        description="IT automation platform",
        primary_purpose="Automation",
        stars_approx=62000,
    ),
    RepoInfo(
        name="httpie",
        github_url="https://github.com/httpie/cli",
        description="Modern HTTP client",
        primary_purpose="CLI tool",
        stars_approx=33000,
    ),
    RepoInfo(
        name="black",
        github_url="https://github.com/psf/black",
        description="Python code formatter",
        primary_purpose="Code formatter",
        stars_approx=38000,
    ),
    RepoInfo(
        name="numpy",
        github_url="https://github.com/numpy/numpy",
        description="Fundamental package for scientific computing",
        primary_purpose="Scientific computing",
        stars_approx=27000,
    ),
]

# Tier 3: Specialist/niche but high-quality
TIER_3_REPOS: List[RepoInfo] = [
    RepoInfo(
        name="mypy",
        github_url="https://github.com/python/mypy",
        description="Static type checker",
        primary_purpose="Type checking",
        stars_approx=18000,
    ),
    RepoInfo(
        name="poetry",
        github_url="https://github.com/python-poetry/poetry",
        description="Python packaging and dependency management",
        primary_purpose="Package manager",
        stars_approx=31000,
    ),
    RepoInfo(
        name="pydantic",
        github_url="https://github.com/pydantic/pydantic",
        description="Data validation using type hints",
        primary_purpose="Data validation",
        stars_approx=20000,
    ),
    RepoInfo(
        name="sqlalchemy",
        github_url="https://github.com/sqlalchemy/sqlalchemy",
        description="SQL toolkit and ORM",
        primary_purpose="Database ORM",
        stars_approx=9000,
    ),
    RepoInfo(
        name="fastapi",
        github_url="https://github.com/tiangolo/fastapi",
        description="Modern web framework",
        primary_purpose="Web API framework",
        stars_approx=75000,
    ),
]


def get_all_repos() -> List[RepoInfo]:
    """Get all repos in evaluation order (tier 1 -> 2 -> 3)."""
    return TIER_1_REPOS + TIER_2_REPOS + TIER_3_REPOS


def get_tier(tier_num: int) -> List[RepoInfo]:
    """Get repos for a specific tier (1, 2, or 3)."""
    if tier_num == 1:
        return TIER_1_REPOS
    elif tier_num == 2:
        return TIER_2_REPOS
    elif tier_num == 3:
        return TIER_3_REPOS
    else:
        raise ValueError(f"Invalid tier: {tier_num}. Must be 1, 2, or 3.")
