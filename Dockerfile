# Use an Ubuntu base image
FROM python:3.12.1-slim

# Set the working directory to /app/AutoPatcher
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install Git and other dependencies
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*


# download submodules
RUN git submodule init && git submodule update

# Install virtualenv and dependencies in the container
RUN pip install --upgrade pip && \
pip install --no-cache-dir -r requirements.txt

# install torch-cpu
RUN pip install torch==2.3.1+cpu -f https://download.pytorch.org/whl/torch_stable.html

# Download the model.bin from google drive
# https://drive.google.com/file/d/1odETLrot-tCNxUoDJsyLuGjGRwsICeZ9/view?usp=sharing
RUN mkdir -p /app/models

RUN gdown '1odETLrot-tCNxUoDJsyLuGjGRwsICeZ9' -O /app/models/model.bin

# Specify the command to run on container start
CMD ["python", "autopatcher.py"]

# docker run -it --rm --name myautopatcher autopatcher