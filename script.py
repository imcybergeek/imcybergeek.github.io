def generateHashWord(
            siteTag,
            masterKey,
            hashWordSize,
            requireDigit,
            requirePunctuation,
            requireMixedCase,
            restrictSpecial,
            restrictDigits):
    # Start with the SHA1-encrypted master key/site tag.
    s = b64_hmac_sha1(masterKey, siteTag)
    # Use the checksum of all characters as a pseudo-randomizing seed to
    # avoid making the injected characters easy to guess.  Note that it
    # isn't random in the sense of not being deterministic (i.e.
    # repeatable).  Must share the same seed between all injected
    # characters so that they are guaranteed unique positions based on
    # their offsets.
    sum = 0
    for i in range(len(s):
        sum += ord(s[i])
    # Restrict digits just does a mod 10 of all the characters
    if restrictDigits:
        s = convertToDigits(s, sum, hashWordSize)
    else:
        # Inject digit, punctuation, and mixed case as needed.
        if requireDigit:
            s = injectSpecialCharacter(s, 0, 4, sum, hashWordSize, 48, 10)
        if requirePunctuation and not restrictSpecial:
            s = injectSpecialCharacter(s, 1, 4, sum, hashWordSize, 33, 15)
        if requireMixedCase:
            s = injectSpecialCharacter(s, 2, 4, sum, hashWordSize, 65, 26)
            s = injectSpecialCharacter(s, 3, 4, sum, hashWordSize, 97, 26)
        # Strip out special characters as needed.
        if restrictSpecial:
            s = removeSpecialCharacters(s, sum, hashWordSize)
    # Trim it to size.
    return s.substr(0, hashWordSize)

# This is a very specialized method to inject a character chosen from a
# range of character codes into a block at the front of a string if one of
# those characters is not already present.
# Parameters:
#  sInput   = input string
#  offset   = offset for position of injected character
#  reserved = # of offsets reserved for special characters
#  seed     = seed for pseudo-randomizing the position and injected character
#  lenOut   = length of head of string that will eventually survive truncation.
#  cStart   = character code for first valid injected character.
#  cNum     = number of valid character codes starting from cStart.
def injectSpecialCharacter(sInput, offset, reserved, seed, lenOut, cStart, cNum):
    pos0 = seed % lenOut
    pos = (pos0 + offset) % lenOut
    # Check if a qualified character is already present
    # Write the loop so that the reserved block is ignored.
    for i in range(lenOut - reserved):
        i2 = (pos0 + reserved + i) % lenOut
        c = ord(sInput[i2])
        if c >= cStart and c < cStart + cNum:
            return sInput   # Already present - nothing to do
    sHead   = sInput[:pos]
    sInject = chr(((seed + ord(sInput[pos])) % cNum) + cStart)
    sTail   = sInput[pos+1:]
    return (sHead + sInject + sTail)

# Another specialized method to replace a class of character, e.g.
# punctuation, with plain letters and numbers.
# Parameters:
#  sInput = input string
#  seed   = seed for pseudo-randomizing the position and injected character
#  lenOut = length of head of string that will eventually survive truncation.
def removeSpecialCharacters(sInput, seed, lenOut):
    s = ''
    for c in sInput:
        if c.isalnum():
            s += c
        else:
            s += chr((seed + len(s)) % 26 + 65)
    return s

# Convert input string to digits-only.
# Parameters:
#  sInput = input string
#  seed   = seed for pseudo-randomizing the position and injected character
#  lenOut = length of head of string that will eventually survive truncation.
def convertToDigits(sInput, seed, lenOut):
    s = ''
    for c in sInput:
        if c.isdigit():
            s += c
        else:
            s += chr((seed + ord(sInput[i])) % 10 + 48)