#!/bin/sh
curl -s https://api.example.com/status | jq .state
