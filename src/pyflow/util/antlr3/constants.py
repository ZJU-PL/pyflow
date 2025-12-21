
EOF = -1

## All tokens go to the parser (unless skip() is called in that rule)
# on a particular "channel".  The parser tunes to a particular channel
# so that whitespace etc... can go to the parser on a "hidden" channel.
DEFAULT_CHANNEL = 0

## Anything on different channel than DEFAULT_CHANNEL is not parsed
# by parser.
HIDDEN_CHANNEL = 99

# Predefined token types
EOR_TOKEN_TYPE = 1

##
# imaginary tree navigation type; traverse "get child" link
DOWN = 2
##
#imaginary tree navigation type; finish with a child list
UP = 3

MIN_TOKEN_TYPE = UP+1
	
INVALID_TOKEN_TYPE = 0

