FROM ubuntu:22.04
LABEL maintainer="Kenneth Dalgaard"


RUN mkdir /projects

#testtest
ADD requirements.txt /usr

RUN apt-get update && apt-get install -y python3=3.10.6-1~22.04 python3-pip curl python-is-python3 sqlite3 iputils-ping python3.10-venv cron nano \

&& pip install --no-cache-dir -r /usr/requirements.txt \
&& pip cache purge \
&& python -m pyclean /usr 



ADD ntc-templates/ /usr/local/lib/python3.10/dist-packages/ntc_templates/templates/


ADD  code/cron/crontab /etc/cron.d/crontab

RUN chmod 644 /etc/cron.d/crontab \ 
&& crontab /etc/cron.d/crontab
