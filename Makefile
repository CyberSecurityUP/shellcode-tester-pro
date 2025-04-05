install:
	sudo apt update
	sudo apt install -y python3 python3-pip python3-venv \
		python3-pyqt5 \
		libcapstone-dev \
		libunicorn-dev \
		nasm \
		x11-utils x11-xserver-utils xterm gnome-terminal konsole \
		build-essential libx11-dev libxcb1-dev libxext-dev libxrender-dev

	pip3 install -r requirements.txt

run:
	export XDG_RUNTIME_DIR="/run/user/$(id -u)"   
	python3 main_gui.py

clean:
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -r {} +
