import os, threading, uuid, sys, argparse, binascii

print("\033[33;1m[COMPILATION] Start all tasks\033[0m")

name = "azuretls"
parser = argparse.ArgumentParser()

parser.add_argument('--key', dest='token', type=str, help='URL of abck page')

scripts = [
    'certs.go',
    'compression.go',
    'connect.go',
    'cookies.go',
    'extern_handler.go',
    'ja3.go',
    'presets.go',
    'requests.go',
    'response.go',
    'server_push.go',
    'session.go',
    'structs.go',
    'transport.go',
    'utils.go'
]

token_files = []

args = parser.parse_args()

token = args.token if args.token else str(binascii.b2a_hex(os.urandom(32)).decode())

for file in scripts:
    with open(os.getcwd()+"/"+file, "r", encoding="utf-8") as filer:
        content = filer.read()
    
    if "TOKEN_TEST" in content:
        content = content.replace("TOKEN_TEST", token)
    
        with open(os.getcwd()+"/"+file.split(".")[0]+"-tmp.go", "w", encoding="utf-8") as filew:
            filew.write(content)
            
        token_files.append(file)
        
platforms = [
    "darwin/amd64",
    "darwin/arm64",
    "linux/amd64",
    "linux/arm64",
    "windows/386",
    "windows/amd64",
    "windows/arm64"
]



threads = len(platforms)

for file in token_files:
    scripts.append(file.split(".")[0]+"-tmp.go")
    scripts.remove(file)

scripts_to_compile = " ".join(scripts)

def compileThisShit(archs):
    for arch in archs:
        information = arch.split("/")
        goos = information[0]
        goarch = information[1]
        
        compiled_name = name + "-" + goos + "-" + goarch
        
        os.system(f"env GOOS={goos} GOARCH={goarch} garble -literals -seed=random -tiny build -o {compiled_name} {scripts_to_compile}")
        
        
elements_per_thread = len(platforms) // threads

threads_platforms_work = []

for i in range(threads):
    threads_platforms_work.append(platforms[i*elements_per_thread:i*elements_per_thread+elements_per_thread])
    
for i, element in enumerate(platforms[-(len(platforms)%threads):]):
    threads_platforms_work[i].append(element)
    
all_threads = []
for thread_platform in threads_platforms_work:
    thread = threading.Thread(target=compileThisShit, args=(thread_platform,))
    thread.start()
    all_threads.append(thread)
    

for element in all_threads:
    element.join()

print("\033[32;1m[COMPILATION] Successfully Compiled !\033[0m")

with open("README.txt", "w", encoding="utf-8") as file:
    file.write("TOKEN : " + token)

print(f"\033[33;1m[COMPILATION] Zip all files into {name}.\033[0m")
os.system(f"zip {name}.zip {name}-* README.txt")
print(f"\033[33;1m[COMPILATION] Successfully zipped all files into {name} !\033[0m")

print("\033[33;1m[COMPILATION] Clean folder.\033[0m")

for file in token_files:
    os.remove(os.getcwd()+"/"+file.split(".")[0]+"-tmp.go")
    
os.remove(os.getcwd()+"/README.txt")
os.system(f"rm {name}-*")

print("\033[33;1m[COMPILATION] Successfully cleaned folder !\033[0m")