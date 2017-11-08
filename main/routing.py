# -*- coding: utf-8 -*-

from channels.routing import route

from . import consumers

channel_routing = [
    route('websocket.connect', consumers.client_register),
    route('websocket.receive', consumers.client_notify),
    route('websocket.disconnect', consumers.client_deregister),
]
