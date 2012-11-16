package main;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Start a server, attach a client, and send a message.
 */
public class PlugServer implements Runnable {
  AtomicBoolean stop;
  int port;
  
  public PlugServer(AtomicBoolean stop, int port) {
    this.stop = stop;
    this.port = port;
  }
  
  public void run() {
    
    System.out.println("Starting server");
    ServerImpl server = null;
    try {
      server = new ServerImpl();
      server.startServer(port);
      while (!stop.get())
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          e.printStackTrace();
          break;
        }
      server.close();
      
      return;
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    } finally {}
    
  }
  
  public static void main(String[] args) {
    new PlugServer(new AtomicBoolean(false), Integer.parseInt(args[0])).run();
  }
}
