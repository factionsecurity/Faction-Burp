package com.fuse.data;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import javax.xml.bind.DatatypeConverter;

public class DataConnection extends URLConnection {

    public DataConnection(URL u) {
        super(u);
    }

    @Override
    public void connect() throws IOException {
        connected = true;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        String data = url.toString();
        data = data.replaceFirst("^.*;base64,", "");
        System.out.println("Data: " + data);
        byte[] bytes = DatatypeConverter.parseBase64Binary(data);
        return new ByteArrayInputStream(bytes);
    }

}