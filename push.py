def WatchChange(service, channel_id, channel_type, channel_address,
                channel_token=None, channel_params=None):
  """Watch for all changes to a user's Drive.

  Args:
    service: Drive API service instance.
    channel_id: Unique string that identifies this channel.
    channel_type: Type of delivery mechanism used for this channel.
    channel_address: Address where notifications are delivered.
    channel_token: An arbitrary string delivered to the target address with
                   each notification delivered over this channel. Optional.
    channel_address: Address where notifications are delivered. Optional.

  Returns:
    The created channel if successful
  Raises:
    apiclient.errors.HttpError: if http request to create channel fails.
  """
  body = {
    'id': channel_id,
    'type': channel_type,
    'address': channel_address
  }
  if channel_token:
    body['token'] = channel_token
  if channel_params:
    body['params'] = channel_params
  return service.changes().watch(body=body).execute()

def WatchFile(service, file_id, channel_id, channel_type, channel_address,
              channel_token=None, channel_params=None):
  """Watch for any changes to a specific file.

  Args:
    service: Drive API service instance.
    file_id: ID of the file to watch.
    channel_id: Unique string that identifies this channel.
    channel_type: Type of delivery mechanism used for this channel.
    channel_address: Address where notifications are delivered.
    channel_token: An arbitrary string delivered to the target address with
                   each notification delivered over this channel. Optional.
    channel_address: Address where notifications are delivered. Optional.

  Returns:
    The created channel if successful
  Raises:
    apiclient.errors.HttpError: if http request to create channel fails.
  """
  body = {
    'id': channel_id,
    'type': channel_type,
    'address': channel_address
  }
  if channel_token:
    body['token'] = channel_token
  if channel_params:
    body['params'] = channel_params
  return service.files().watch(fileId=file_id, body=body).execute()

def StopChannel(service, channel_id, resource_id):
  """Stop watching to a specific channel.

  Args:
    service: Drive API service instance.
    channel_id: ID of the channel to stop.
    resource_id: Resource ID of the channel to stop.
  Raises:
    apiclient.errors.HttpError: if http request to create channel fails.
  """
  body = {
    'id': channel_id,
    'resourceId': resource_id
  }
  service.channels().stop(body=body).execute()
