# -*- coding: utf-8 -*-

import logging

from channels import Group


logger = logging.getLogger(__name__)


def client_register(message):
    # log that we got the connection
    logger.info('WebSocket connection received')
    # accept connection
    message.reply_channel.send({'accept': True})
    # join the reply channel to the group
    Group('EDD').add(message.reply_channel)


def client_notify(message):
    # log that we got the message
    logger.info('WebSocket message received: %s', message.content)
    # forward to the group
    Group('EDD').send({
        'text': '[EDD] %s' % message.content['text'],
    })


def client_deregister(message):
    # log the disconnect
    logger.info('WebSocket connection disconnected')
    # depart the group
    Group('EDD').discard(message.reply_channel)
