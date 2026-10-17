package org.kodein.emoji.symbols.other_symbol

import org.kodein.emoji.Emoji
import org.kodein.emoji.EmojiImpl
import org.kodein.emoji.UnicodeVersion
import org.kodein.emoji.EmojiFinder


internal val _Copyright: Emoji = EmojiImpl(
    details = Emoji.Details(
        string = "©️",
        description = "copyright",
        unicodeVersion = UnicodeVersion(0, 6),
        aliases = listOf("copyright", ),
        emoticons = listOf(),
        notoImageRatio = 0.0f,
        notoAnimationRatio = 0.0f,
    ),
)

/**
 * Emoji Symbols: other-symbol: copyright.
 *
 * Preferred type is: fully-qualified.
*/
public val Emoji.Companion.Copyright: Emoji get() = _Copyright
