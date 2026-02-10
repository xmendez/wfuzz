FROM python:3.9-alpine3.12 as builder

RUN apk add --no-cache build-base curl-dev

COPY . wfuzz/

WORKDIR wfuzz/

RUN python setup.py install


FROM python:3.9-alpine3.12

RUN apk add --no-cache curl-dev

COPY --from=builder /usr/local /usr/local

CMD wfuzz
