#!/bin/sh

if [ `pgrep -f finder.py` ];
then
    echo "### FreeDom is already running!!"
    exit 1
else
#    source ~/miniconda3/etc/profile.d/conda.sh
    source /opt/miniconda3/etc/profile.d/conda.sh
    conda activate SocialPy
    nohup nice bash -c "python finder.py" &
    exit 0
fi