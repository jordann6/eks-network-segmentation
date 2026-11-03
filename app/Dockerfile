# One image for every role (see lab.py). curl and bind-tools are the attacker's
# tooling inside the foothold; they ship in every role so no pod can be told
# apart by its tools, only by its labels and identity.
FROM python:3.12-alpine3.22
RUN apk add --no-cache curl bind-tools \
 && adduser -D -u 10001 lab
COPY lab.py /app/lab.py
USER 10001
EXPOSE 8080
ENTRYPOINT ["python3", "-u", "/app/lab.py"]
