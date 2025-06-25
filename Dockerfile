FROM python:3.12-alpine as builder

RUN apk add --no-cache build-base curl-dev

COPY . wfuzz/

WORKDIR wfuzz/

RUN python setup.py install


FROM python:3.12-alpine

RUN apk add --no-cache curl-dev

COPY --from=builder /usr/local /usr/local

CMD wfuzz
