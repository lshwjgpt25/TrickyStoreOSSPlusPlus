/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException
import org.xmlpull.v1.XmlPullParserFactory
import java.io.IOException
import java.io.StringReader

class XmlParser(private val xmlContent: String) {
    
    sealed class ParseResult {
        data class Success(val attributes: Map<String, String>) : ParseResult()
        data class Error(val message: String, val cause: Throwable? = null) : ParseResult()
    }
    
    fun obtainPath(path: String): ParseResult {
        return try {
            val factory = XmlPullParserFactory.newInstance()
            val parser = factory.newPullParser()
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false)
            parser.setInput(StringReader(xmlContent))
            
            val tags = path.split(".").toTypedArray()
            val result = readData(parser, tags, 0, mutableMapOf())
            ParseResult.Success(result)
        } catch (e: XmlPullParserException) {
            ParseResult.Error("XML parsing error: ${e.message}", e)
        } catch (e: IOException) {
            ParseResult.Error("IO error while parsing XML: ${e.message}", e)
        } catch (e: Exception) {
            ParseResult.Error("Unexpected error: ${e.message}", e)
        }
    }
    
    @Throws(Exception::class)
    fun obtainPathLegacy(path: String): Map<String, String> {
        when (val result = obtainPath(path)) {
            is ParseResult.Success -> return result.attributes
            is ParseResult.Error -> throw result.cause ?: Exception(result.message)
        }
    }
    
    @Throws(IOException::class, XmlPullParserException::class)
    private fun readData(
        parser: XmlPullParser,
        tags: Array<String>,
        index: Int,
        tagCounts: MutableMap<String, Int>
    ): Map<String, String> {
        while (parser.next() != XmlPullParser.END_DOCUMENT) {
            if (parser.eventType != XmlPullParser.START_TAG) {
                continue
            }
            
            val currentTag = parser.name ?: continue
            val targetTag = tags[index]
            val tagParts = targetTag.split("[")
            val baseTagName = tagParts[0]
            
            if (currentTag == baseTagName) {
                return if (tagParts.size > 1) {
                    handleIndexedTag(parser, tags, index, tagCounts, currentTag, tagParts[1])
                } else {
                    handleRegularTag(parser, tags, index)
                }
            } else {
                skipCurrentElement(parser)
            }
        }
        
        throw XmlPullParserException("Path not found: ${tags.joinToString(".")}")
    }
    
    @Throws(IOException::class, XmlPullParserException::class)
    private fun handleIndexedTag(
        parser: XmlPullParser,
        tags: Array<String>,
        index: Int,
        tagCounts: MutableMap<String, Int>,
        currentTag: String,
        indexPart: String
    ): Map<String, String> {
        val targetIndex = indexPart.replace("]", "").toIntOrNull()
            ?: throw XmlPullParserException("Invalid index in tag: $indexPart")
        
        val currentCount = tagCounts.getOrDefault(currentTag, 0)
        
        return if (currentCount < targetIndex) {
            tagCounts[currentTag] = currentCount + 1
            readData(parser, tags, index, tagCounts)
        } else {
            if (index == tags.size - 1) {
                readAttributes(parser)
            } else {
                readData(parser, tags, index + 1, tagCounts)
            }
        }
    }
    
    @Throws(IOException::class, XmlPullParserException::class)
    private fun handleRegularTag(
        parser: XmlPullParser,
        tags: Array<String>,
        index: Int
    ): Map<String, String> {
        return if (index == tags.size - 1) {
            readAttributes(parser)
        } else {
            readData(parser, tags, index + 1, mutableMapOf())
        }
    }
    
    @Throws(IOException::class, XmlPullParserException::class)
    private fun readAttributes(parser: XmlPullParser): Map<String, String> {
        val attributes = mutableMapOf<String, String>()
        
        for (i in 0 until parser.attributeCount) {
            val name = parser.getAttributeName(i)
            val value = parser.getAttributeValue(i)
            if (name != null && value != null) {
                attributes[name] = value
            }
        }
        
        if (parser.next() == XmlPullParser.TEXT) {
            parser.text?.let { text ->
                attributes["text"] = text
            }
        }
        
        return attributes
    }
    
    @Throws(XmlPullParserException::class, IOException::class)
    private fun skipCurrentElement(parser: XmlPullParser) {
        if (parser.eventType != XmlPullParser.START_TAG) {
            throw IllegalStateException("Parser must be positioned at START_TAG")
        }
        
        var depth = 1
        while (depth != 0) {
            when (parser.next()) {
                XmlPullParser.END_TAG -> depth--
                XmlPullParser.START_TAG -> depth++
            }
        }
    }
}

fun String.toXmlParser(): XmlParser = XmlParser(this)