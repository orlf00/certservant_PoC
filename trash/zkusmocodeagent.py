import asyncio
from pathlib import Path

from browser_use import ChatBrowserUse, CodeAgent
from browser_use.code_use.notebook_export import session_to_python_script
from browser_use.filesystem.file_system import FileSystem
from dotenv import load_dotenv

load_dotenv()
async def main():
    fs=FileSystem(base_dir=Path("/crt/ptz1.kme.vse.cz"))
    agent = CodeAgent(
        task='Go to ptz1.kme.vse.cz login there with username= "admin" password= "4w97gKthFRg46g5", then click on the "camera config", the "system settings" will append, click on it, in the next page you will see "select file from your computer", upload there the file and click on apply and then on reboot.',
        available_file_paths=["/Users/filiporlicky/PycharmProjects/FlaskProjectPTZ/crt/ptz1.kme.vse.cz/ssl.pem"],
        llm=ChatBrowserUse(),
        max_steps=20,
        file_system=fs,
    )

    # Run your automation
    await agent.run()

    # Export to Python script
    python_script = session_to_python_script(agent)
    with open("product_scraping.py", "w") as f:
        f.write(python_script)

if __name__ == "__main__":
    asyncio.run(main())
