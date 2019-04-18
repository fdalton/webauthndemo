package com.google.webauthn.gaedemo.custom;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.internal.Streams;

import java.io.EOFException;
import java.util.NoSuchElementException;

public class FrankensteinExceptions {
    /**
     * Returns the next available {@link JsonElement} on the reader. Null if none available.
     *
     * @return the next available {@link JsonElement} on the reader. Null if none available.
     * @throws JsonParseException if the incoming stream is malformed JSON.
     * @since 1.4
     */
    public JsonElement next() throws JsonParseException {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        try {
            return Streams.parse(parser);
        } catch (StackOverflowError e) {
            throw new JsonParseException("Failed parsing JSON source to Json", e);
        } catch (OutOfMemoryError e) {
            throw new JsonParseException("Failed parsing JSON source to Json", e);
        } catch (JsonParseException e) {
            throw e.getCause() instanceof EOFException ? new NoSuchElementException() : e;
        }
    }
}
