FROM python:3.11-alpine3.21 as builder
RUN apk add --no-cache build-base curl-dev
COPY . wfuzz/
WORKDIR wfuzz/
RUN python setup.py install
FROM python:3.11-alpine3.21
RUN apk add --no-cache curl-dev
COPY --from=builder /usr/local /usr/local
CMD wfuzz