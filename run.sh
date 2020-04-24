# activate Conda env
source ~/miniconda3/etc/profile.d/conda.sh 
conda activate SocialPy

nohup nice bash -c "python finder.py" &
