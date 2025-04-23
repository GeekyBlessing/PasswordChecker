#!/usr/bin/env python3
"""Password Strength Checker: Evaluates password security based on length, complexity, entropy, and patterns."""
import re
import math
import string
import argparse
from typing import Dict, List, Set
from pathlib import Path
import logging
from rich.console import Console
from rich.table import Table
try:
    from rich.console import Console
    from rich.table import Table
    # Verify console.input exists
    if not hasattr(Console(), 'input'):
        raise AttributeError("The installed 'rich' version is too old. Please upgrade with 'pip install --upgrade rich'.")
except ImportError:
    print("Error: 'rich' library is required. Install it with 'pip install rich'.")
    exit(1)
# Configuration constants
MIN_LENGTH: int = 8
RECOMMENDED_LENGTH: int = 12
ENTROPY_THRESHOLD_WEAK: float = 50.0
ENTROPY_THRESHOLD_STRONG: float = 80.0
CHARSET_SIZES: Dict[str, int] = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "special": 32,
}

# Setup logging (avoid printing passwords in production)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)
console = Console()
import os

class PasswordAnalyzer:
    """Class to analyze password strength and provide detailed feedback."""
    
    def __init__(self, file=None, common_passwords_file: str = "common_passwords.txt"):
        """Initialize with a file containing common passwords."""
        self.common_passwords: Set[str] = self._load_common_passwords(common_passwords_file)
    
    def _load_common_passwords(self, file_path: str) -> Set[str]:
        """Load common passwords from a file."""
        try:
            if Path(file_path).exists():
                with open(file_path, "r", encoding="utf-8") as f:
                    return {line.strip().lower() for line in f if line.strip()}
            logger.warning("Common passwords file not found. Using minimal set.")
            return {"password", "123456", "qwerty", "admin123", "letmein"}
        except Exception as e:
            logger.error(f"Error loading common passwords: {e}")
            return set()

    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += CHARSET_SIZES["lowercase"]
        if re.search(r"[A-Z]", password):
            charset_size += CHARSET_SIZES["uppercase"]
        if re.search(r"[0-9]", password):
            charset_size += CHARSET_SIZES["digits"]
        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += CHARSET_SIZES["special"]
        
        if charset_size == 0:
            return 0.0
        return round(len(password) * math.log2(charset_size), 2)

    def check_patterns(self, password: str) -> bool:
        """Check for predictable patterns (e.g., repeated characters, sequences)."""
        # Check for repeated characters (e.g., "aaa")
        if re.search(r"(.)\1{2,}", password):
            return True
        # Check for sequential characters (e.g., "abc" or "123")
        if any(sub in password.lower() for sub in ["abc", "123", "qwe", "asdf"]):
            return True
        return False

    def analyze(self, password: str) -> Dict[str, any]:
        """Analyze password strength and return detailed results."""
        if not password:
            return {"strength": "Invalid", "score": 0, "entropy": 0.0, "feedback": ["Password cannot be empty."]}

        feedback: List[str] = []
        score: int = 0

        # Length checks
        if len(password) < MIN_LENGTH:
            feedback.append(f"Password too short. Use at least {MIN_LENGTH} characters.")
        elif len(password) >= RECOMMENDED_LENGTH:
            feedback.append(f"Excellent! Password length is strong ({RECOMMENDED_LENGTH}+ characters).")
            score += 3
        else:
            feedback.append(f"Good length, but consider {RECOMMENDED_LENGTH}+ characters.")
            score += 1

        # Character type checks
        checks = [
            (r"[a-z]", "lowercase letters", 1),
            (r"[A-Z]", "uppercase letters", 1),
            (r"[0-9]", "numbers", 1),
            (r"[^a-zA-Z0-9]", "special characters", 2),
        ]
        for pattern, desc, points in checks:
            if re.search(pattern, password):
                feedback.append(f"Contains {desc}: Good.")
                score += points
            else:
                feedback.append(f"Add {desc} for better strength.")

        # Common password and pattern checks
        if password.lower() in self.common_passwords:
            feedback.append("WARNING: Common password detected! Easily guessable.")
            score = 0
        elif self.check_patterns(password):
            feedback.append("WARNING: Predictable pattern detected (e.g., sequences).")
            score = min(score, 2)

        # Entropy calculation
        entropy = self.calculate_entropy(password)
        feedback.append(f"Password entropy: {entropy} bits.")
        if entropy < ENTROPY_THRESHOLD_WEAK:
            feedback.append("Low entropy; use a longer or more complex password.")
        elif entropy >= ENTROPY_THRESHOLD_STRONG:
            feedback.append("High entropy: Excellent brute-force resistance!")
            score += 2

        # Strength rating
        strength = "Strong" if score >= 10 else "Moderate" if score >= 6 else "Weak"

        return {
            "strength": strength,
            "score": score,
            "entropy": entropy,
            "feedback": feedback,
        }

def display_results(result: Dict[str, any]) -> None:
    """Display analysis results using a rich table."""
    table = Table(title="Password Analysis", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Strength", result["strength"])
    table.add_row("Score", f"{result['score']}/12")
    table.add_row("Entropy", f"{result['entropy']} bits")
    
    console.print(table)
    
    console.print("\n[bold]Feedback:[/bold]")
    for item in result["feedback"]:
        console.print(f"- {item}", style="yellow" if "WARNING" in item else "white")
    
    console.print("\n[bold]Recommendations:[/bold]")
    console.print("- Use a mix of uppercase, lowercase, numbers, and special characters.")
    console.print(f"- Aim for {RECOMMENDED_LENGTH}+ characters and entropy >{ENTROPY_THRESHOLD_STRONG} bits.")
    console.print("- Avoid common passwords or predictable patterns.")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Password Strenght Checker")
    parser.add_argument("--file",help="File containing passwords to chcek")
    parser.add_argument("--common-passwords-file", default="common_passwords.txt", help="file containing  common passwords")
    args = parser.parse_args()

    analyzer = PasswordAnalyzer(args.file, common_passwords_file=args.common_passwords_file)
    
    while True:
        try:
            password = console.input("Enter password: ").strip()
            if password.lower() == 'q':
                console.print("Exiting Password Checker. Stay secure!", style="bold green")
                break
            result = analyzer.analyze(password)
            display_results(result)
            console.print("\n" + "=" * 40 + "\n")
        except KeyboardInterrupt:
            console.print("\nExiting Password Checker. Stay secure!", style="bold green")
            break
        except Exception as e:
            logger.error(f"Error: {e}")
            console.print("An error occurred. Please try again.", style="bold red")

if __name__== "__main__":
    main()