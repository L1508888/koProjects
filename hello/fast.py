import os
import subprocess
import sys




def run_cmd(cmd):
    print(f"execve cmd {cmd}")
    result = subprocess.run(cmd, shell=True, text=true, capture_output=True)
    if result.returncode != 0:
        print("error ", result.stderr)
        sys.exit(result.returncode)
    if result.stdout:
        print(result.stdout)
    

def main():
    # 确定要推送的文件（默认 a.out，可通过命令行参数指定）
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        target_file = "a.out"

        
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"current dir {script_dir}")
    run_cmd("make")
    target_file = f"".ko



print(os.getcwd())