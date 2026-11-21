"""
BugHunter AI -- Main Entry Point
"""

import os
import sys
import io

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(__file__))

def main():
    print("BugHunter AI -- Starting...")
    try:
        from gui.simple_app import BugHunterSimple
        app = BugHunterSimple()
        app.mainloop()
    except ImportError as e:
        print(f"Missing dependencies: {e}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
