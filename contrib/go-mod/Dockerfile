FROM docker.io/library/golang:1.13.15

RUN apt update \
    && apt install -y jq \
    && true

ENV XDG_CACHE_HOME="/tmp/.cache"

CMD ["/bin/bash"]
