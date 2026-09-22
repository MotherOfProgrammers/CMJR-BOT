from message_parser import parse_message

message = parse_message(
    sender="123456789",
    text="  Hello bot!  ",
)

print(message)
print(message.sender)
print(message.text)
