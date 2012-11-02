package main;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.ByteBuffer;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TCompactProtocol;
import org.apache.thrift.server.THsHaServer;
import org.apache.thrift.server.TServer;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TNonblockingServerSocket;

import thrift.PlugException;
import thrift.PluggableSecurityTest;
import tokens.Token;
import authenticators.Authenticator;
import authenticators.UserPassAuthenticator;

;

public class ServerImpl implements PluggableSecurityTest.Iface {
  Authenticator auth = new UserPassAuthenticator();
  // Authenticator auth = new TicketAuthenticator();
  boolean last = false;
  TServer server;
  
  @Override
  public boolean ping() throws TException {
    last = !last;
    return last;
  }
  
  @Override
  public boolean authenticate(ByteBuffer tokenBytes) throws PlugException, TException {
    return auth.authenticate(getToken(tokenBytes));
  }
  
  private Token getToken(ByteBuffer tokenBytes) throws TException {
    ByteArrayInputStream byteIn = new ByteArrayInputStream(tokenBytes.array());
    ObjectInputStream in;
    try {
      in = new ObjectInputStream(byteIn);
      Token token = (Token) in.readObject();
      in.close();
      byteIn.close();
      return token;
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
      throw new TException(e);
    } catch (ClassNotFoundException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
      throw new TException(e);
    }
  }
  
  public void startServer(final Integer port) throws Exception {
    TNonblockingServerSocket socket = new TNonblockingServerSocket(port);
    final PluggableSecurityTest.Processor<PluggableSecurityTest.Iface> processor = new PluggableSecurityTest.Processor<PluggableSecurityTest.Iface>(this);
    
    THsHaServer.Args args = new THsHaServer.Args(socket);
    args.processor(processor);
    args.transportFactory(new TFramedTransport.Factory());
    args.protocolFactory(new TCompactProtocol.Factory());
    server = new THsHaServer(args);
    
    Thread t = new Thread("thrift server") {
      public void run() {
        System.out.println("Starting server on port " + port + " ...");
        server.serve();
      }
    };
    t.start();
    
  }
  
  public ServerImpl() {
    
  }
  
  public void close() {
    server.stop();
  }
  
  @Override
  public boolean nonauthenticateoperation(String user, ByteBuffer token, String operationRelatedData) throws PlugException, TException {
    if (auth.validateUser(user, getToken(token))) {
      System.out.println(operationRelatedData);
      return true;
    }
    return false;
  }
}
