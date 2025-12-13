package com.projetmessagerie.vertimail;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.datagram.DatagramSocket;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.templ.pebble.PebbleTemplateEngine;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class MainVerticle extends AbstractVerticle {

  PebbleTemplateEngine engine;
  Map<String, Integer> ipCounts = new HashMap<>();

  // Regex pour la validation du mot de passe
  private static final Pattern PASSWORD_PATTERN =
      Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$");

  @Override
  public void start(Promise<Void> startPromise) throws Exception {
    System.out.println("🚀 Démarrage de l'application...");

    engine = PebbleTemplateEngine.create(vertx);
    Router router = Router.router(vertx);
    router.route().handler(BodyHandler.create());

    // --- ROUTE CSS (Indispensable pour le design) ---
    router.get("/style.css").handler(ctx -> {
      vertx.fileSystem().readFile("src/main/resources/style.css")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/css").end(buffer))
        .onFailure(err -> ctx.response().sendFile("style.css"));
    });

    // --- ROUTES WEB ---

    router.get("/").handler(ctx -> {
      // On récupère le paramètre "success" s'il existe
      String success = ctx.request().getParam("success");
      if (success != null && success.equals("created")) {
          ctx.put("success", "Compte créé avec succès ! Connectez-vous.");
      }
      engine.render(ctx.data(), "templates/login.peb")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/html").end(buffer));
    });

    router.get("/register").handler(ctx -> {
      engine.render(ctx.data(), "templates/register.peb")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/html").end(buffer));
    });

    router.post("/register").handler(ctx -> {
        String username = ctx.request().getFormAttribute("username");
        String password = ctx.request().getFormAttribute("password");
        String confirmPassword = ctx.request().getFormAttribute("confirmPassword");

        if (username == null || username.trim().isEmpty() || password == null) {
            ctx.response().end("Erreur : Pseudo ou mot de passe vide.");
            return;
        }

        // 1. Vérifier si les mots de passe correspondent
        if (!password.equals(confirmPassword)) {
            ctx.response().end("Erreur : Les mots de passe ne correspondent pas.");
            return;
        }

        // 2. Vérifier la complexité du mot de passe
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            ctx.response().end("Erreur : Le mot de passe doit contenir au moins 8 caractères, une majuscule, un chiffre et un symbole (@#$%^&+=!).");
            return;
        }

        String base = "storage/" + username;
        vertx.fileSystem().exists(base).onSuccess(exists -> {
            if (exists) {
                ctx.response().end("Erreur : Pseudo pris !");
            } else {
                vertx.fileSystem().mkdirs(base + "/inbox").onSuccess(v -> {
                    vertx.fileSystem().mkdirs(base + "/outbox");
                    vertx.fileSystem().mkdirs(base + "/draft");
                    vertx.fileSystem().mkdirs(base + "/trash");
                    String hash = hashPassword(password);
                    vertx.fileSystem().writeFile(base + "/password.hash", Buffer.buffer(hash))
                        .onSuccess(vv -> {
                            // Redirection vers la page de login avec un paramètre de succès
                            ctx.redirect("/?success=created");
                        });
                });
            }
        });
    });

    router.post("/login").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      String hashPath = "storage/" + username + "/password.hash";

      vertx.fileSystem().exists(hashPath).onSuccess(exists -> {
        if (!exists) {
          ctx.put("error", "Compte inexistant.");
          engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
        } else {
          vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
            if (buffer.toString().equals(hashPassword(password))) {
              ctx.redirect("/box?username=" + username + "&folder=inbox");
            } else {
              ctx.put("error", "Mot de passe faux.");
              engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
            }
          });
        }
      });
    });


    router.get("/compose").handler(ctx -> {
        String user = ctx.request().getParam("user");
        String recipient = ctx.request().getParam("recipient");
        String subject = ctx.request().getParam("subject");

        ctx.put("username", user);
        if (recipient != null) ctx.put("recipient", recipient);
        if (subject != null) ctx.put("subject", subject);

        // Calculer le nombre de messages non lus pour le menu
        countUnread(user).onSuccess(count -> {
            ctx.put("unreadCount", count);
            engine.render(ctx.data(), "templates/compose.peb").onSuccess(buf -> ctx.response().end(buf));
        }).onFailure(err -> {
            ctx.put("unreadCount", 0);
            engine.render(ctx.data(), "templates/compose.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    router.post("/send").handler(ctx -> {
      String sender = ctx.request().getFormAttribute("sender");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      String content = ctx.request().getFormAttribute("content");
      JsonObject mail = new JsonObject().put("from", sender).put("to", recipient)
        .put("date", java.time.Instant.now().toString()).put("subject", subject).put("content", content);
      String filename = System.currentTimeMillis() + ".json";
      vertx.fileSystem().writeFile("storage/" + recipient + "/inbox/" + filename, mail.toBuffer())
        .onSuccess(v -> vertx.fileSystem().writeFile("storage/" + sender + "/outbox/" + filename, mail.toBuffer())
          .onSuccess(v2 -> ctx.redirect("/box?username=" + sender + "&folder=outbox"))
          .onFailure(e -> ctx.response().end("Erreur outbox")))
        .onFailure(e -> ctx.response().end("Erreur destinataire"));
    });

    router.post("/draft").handler(ctx -> {
      String sender = ctx.request().getFormAttribute("sender");
      String content = ctx.request().getFormAttribute("content");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      JsonObject mail = new JsonObject().put("from", sender).put("to", recipient == null ? "" : recipient)
        .put("date", java.time.Instant.now().toString()).put("subject", subject).put("content", content);
      vertx.fileSystem().writeFile("storage/" + sender + "/draft/" + System.currentTimeMillis() + ".json", mail.toBuffer())
        .onSuccess(v -> ctx.redirect("/box?username=" + sender + "&folder=draft"));
    });

    router.post("/delete").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String folder = ctx.request().getFormAttribute("folder");
      String filename = ctx.request().getFormAttribute("filename");
      String path = "storage/" + username + "/" + folder + "/" + filename;
      if ("trash".equals(folder)) vertx.fileSystem().delete(path).onSuccess(v -> ctx.redirect("/box?username=" + username + "&folder=" + folder));
      else vertx.fileSystem().move(path, "storage/" + username + "/trash/" + filename).onSuccess(v -> ctx.redirect("/box?username=" + username + "&folder=" + folder));
    });

    router.get("/read").handler(ctx -> {
        String username = ctx.request().getParam("username");
        String folder = ctx.request().getParam("folder");
        String id = ctx.request().getParam("id");
        String path = "storage/" + username + "/" + folder + "/" + id;

        vertx.fileSystem().readFile(path)
            .compose(buffer -> {
                JsonObject mail = new JsonObject(buffer);
                // Si le message n'est pas lu, on le met à jour
                if (mail.getBoolean("isRead", false) == false) {
                    mail.put("isRead", true);
                    return vertx.fileSystem().writeFile(path, mail.toBuffer())
                        .map(v -> mail); // On continue avec le mail mis à jour
                } else {
                    return Future.succeededFuture(mail); // On continue avec le mail tel quel
                }
            })
            .compose(mail -> {
                // Après avoir lu (et potentiellement marqué comme lu), on recompte les non-lus
                return countUnread(username).map(count -> {
                    ctx.put("username", username)
                       .put("folder", folder)
                       .put("id", id)
                       .put("mail", mail)
                       .put("unreadCount", count);
                    return null;
                });
            })
            .onSuccess(v -> {
                engine.render(ctx.data(), "templates/read.peb")
                      .onSuccess(buf -> ctx.response().end(buf));
            })
            .onFailure(err -> {
                ctx.response().setStatusCode(500).end("Erreur lors de la lecture du message: " + err.getMessage());
            });
    });

    router.get("/box").handler(ctx -> {
      String username = ctx.request().getParam("username");
      String folder = ctx.request().getParam("folder") == null ? "inbox" : ctx.request().getParam("folder");
      String folderPath = "storage/" + username + "/" + folder;
      final String currentFolder = folder;

      // 1. Lire le dossier courant pour l'affichage
      Future<List<JsonObject>> currentFolderFuture = vertx.fileSystem().readDir(folderPath).compose(files -> {
          List<JsonObject> mails = new ArrayList<>();
          Future<Void> chain = Future.succeededFuture();
          for (String path : files) {
              chain = chain.compose(v -> vertx.fileSystem().readFile(path).map(buf -> {
                  try {
                      JsonObject json = new JsonObject(buf);
                      json.put("id", new File(path).getName());
                      mails.add(json);
                  } catch (Exception e) {}
                  return null;
              }));
          }
          return chain.map(v -> mails);
      });

      // 2. Compter les non-lus
      Future<Long> unreadCountFuture = countUnread(username);

      Future.all(currentFolderFuture, unreadCountFuture).onSuccess(composite -> {
          List<JsonObject> mails = composite.resultAt(0);
          Long unreadCount = composite.resultAt(1);

          // TRI DES MESSAGES
          mails.sort((m1, m2) -> {
              String id1 = m1.getString("id");
              String id2 = m2.getString("id");
              return id2.compareTo(id1);
          });

          ctx.put("username", username)
             .put("mails", mails)
             .put("folder", currentFolder)
             .put("unreadCount", unreadCount);

          engine.render(ctx.data(), "templates/inbox.peb")
            .onSuccess(buf -> ctx.response().end(buf))
            .onFailure(err -> {
                err.printStackTrace();
                ctx.response().setStatusCode(500).end("Erreur d'affichage");
            });
      }).onFailure(err -> {
          ctx.put("username", username).put("mails", new ArrayList<>()).put("folder", currentFolder).put("unreadCount", 0);
          engine.render(ctx.data(), "templates/inbox.peb").onSuccess(buf -> ctx.response().end(buf));
      });
    });

    // ================================================================
    // --- API MOBILE (Pour l'application Android en mode connecté) ---
    // ================================================================

    router.post("/api/login").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      String hashPath = "storage/" + username + "/password.hash";

      vertx.fileSystem().exists(hashPath).onSuccess(exists -> {
        if (!exists) {
          ctx.json(new JsonObject().put("status", "error").put("message", "Utilisateur inconnu"));
        } else {
          vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
            if (buffer.toString().equals(hashPassword(password))) {
              ctx.json(new JsonObject().put("status", "ok").put("username", username));
            } else {
              ctx.json(new JsonObject().put("status", "error").put("message", "Mauvais mot de passe"));
            }
          });
        }
      });
    });

    router.post("/api/send").handler(ctx -> {
      String sender = ctx.request().getFormAttribute("sender");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      String content = ctx.request().getFormAttribute("content");

      vertx.fileSystem().exists("storage/" + recipient).onSuccess(exists -> {
        if (exists) {
          JsonObject mail = new JsonObject()
            .put("from", sender)
            .put("to", recipient)
            .put("date", java.time.Instant.now().toString())
            .put("subject", subject)
            .put("content", content)
            .put("isRead", false); // Important: Le nouveau message est marqué comme NON LU

          String filename = System.currentTimeMillis() + ".json";
          String inboxPath = "storage/" + recipient + "/inbox/" + filename;
          String outboxPath = "storage/" + sender + "/outbox/" + filename;

          // Le message dans la boîte d'envoi de l'expéditeur est considéré comme "lu"
          JsonObject outboxMail = mail.copy().put("isRead", true);

          vertx.fileSystem().writeFile(inboxPath, mail.toBuffer())
            .onSuccess(v -> {
              vertx.fileSystem().writeFile(outboxPath, outboxMail.toBuffer());
              ctx.json(new JsonObject().put("status", "ok"));
            });
        } else {
          ctx.json(new JsonObject().put("status", "error").put("message", "Destinataire introuvable"));
        }
      });
    });

    router.get("/api/mails").handler(ctx -> {
      String username = ctx.request().getParam("username");
      String folder = ctx.request().getParam("folder"); // "inbox" ou "outbox"

      if (username == null || folder == null) {
        ctx.json(new JsonObject().put("status", "error").put("message", "Manque username ou folder"));
        return;
      }

      String path = "storage/" + username + "/" + folder;

      vertx.fileSystem().exists(path).onSuccess(exists -> {
        if (exists) {
          vertx.fileSystem().readDir(path).onSuccess(files -> {
            List<JsonObject> mailList = new ArrayList<>();
            // On lit tous les fichiers
            List<Future<Void>> futures = new ArrayList<>();

            for (String filePath : files) {
                Promise<Void> p = Promise.promise();
                futures.add(p.future());
                vertx.fileSystem().readFile(filePath).onSuccess(buffer -> {
                    try {
                        JsonObject mailJson = new JsonObject(buffer.toString());
                        // On ajoute le nom du fichier comme ID, utile pour le tri
                        mailJson.put("id", new File(filePath).getName());
                        synchronized(mailList) {
                            mailList.add(mailJson);
                        }
                    } catch (Exception e) {
                        // fichier ignoré
                    }
                    p.complete();
                }).onFailure(err -> p.complete());
            }

            // Quand tout est lu
            Future.all(futures).onSuccess(v -> {
                // TRI DES MESSAGES (Plus récent en premier)
                mailList.sort((m1, m2) -> {
                    String id1 = m1.getString("id");
                    String id2 = m2.getString("id");
                    return id2.compareTo(id1);
                });

                ctx.json(new JsonObject().put("status", "ok").put("mails", new JsonArray(mailList)));
            });
          });
        } else {
          ctx.json(new JsonObject().put("status", "ok").put("mails", new JsonArray()));
        }
      }).onFailure(err -> ctx.json(new JsonObject().put("status", "error")));
    });
    // MODIFICATION 2: Nouvelle route pour marquer un message comme lu
    router.post("/api/read").handler(ctx -> {
        String username = ctx.request().getFormAttribute("username");
        String folder = ctx.request().getFormAttribute("folder");
        String filename = ctx.request().getFormAttribute("filename");

        if(username == null || folder == null || filename == null) {
            ctx.json(new JsonObject().put("status", "error").put("message", "Infos manquantes"));
            return;
        }
        String path = "storage/" + username + "/" + folder + "/" + filename;
        vertx.fileSystem().readFile(path)
            .compose(buffer -> {
                JsonObject mail = new JsonObject(buffer);
                mail.put("isRead", true); // On met à jour le statut
                return vertx.fileSystem().writeFile(path, mail.toBuffer()); // On ré-écrit le fichier
            })
            .onSuccess(v -> ctx.json(new JsonObject().put("status", "ok")))
            .onFailure(err -> ctx.json(new JsonObject().put("status", "error").put("message", err.getMessage())));
    });

    // --- SERVEUR UDP ---
    DatagramSocket socket = vertx.createDatagramSocket();
    socket.listen(9999, "0.0.0.0").onSuccess(so -> {
      System.out.println("👻 Serveur UDP anonyme écoute sur le port 9999 (Toutes interfaces)");
      socket.handler(packet -> {
        // === LA LIGNE DE DÉBOGAGE EST ICI ===
        System.out.println("✅ Paquet UDP reçu de: " + packet.sender().host());

        String ip = packet.sender().host();
        int port = packet.sender().port();

        int currentCount = ipCounts.getOrDefault(ip, 0);
        if (currentCount >= 10) {
          System.out.println("⛔ Spam bloqué depuis " + ip);
          socket.send(Buffer.buffer("Erreur : Limite de 10 messages par jour atteinte."), port, ip);
          return;
        }
        ipCounts.put(ip, currentCount + 1);

        String data = packet.data().toString();
        String[] lines = data.split("\n", 3);
        if (lines.length >= 3) {
          String recipient = lines[0].trim();
          String subject = lines[1].trim();
          String content = lines[2].trim();

          // MODIFICATION 3: On ajoute aussi "isRead: false" pour les messages UDP
          JsonObject mail = new JsonObject()
            .put("from", "Anonyme (" + packet.sender().host() + ")")
            .put("to", recipient)
            .put("date", java.time.Instant.now().toString())
            .put("subject", "[UDP] " + subject)
            .put("content", content)
            .put("isRead", false); // Important: Les messages anonymes sont aussi non lus

          String filename = "udp_" + System.currentTimeMillis() + ".json";
          String path = "storage/" + recipient + "/inbox/" + filename;

          vertx.fileSystem().exists("storage/" + recipient + "/inbox").onSuccess(exists -> {
            if (exists) {
              vertx.fileSystem().writeFile(path, mail.toBuffer()).onSuccess(v -> {
                System.out.println("👻 Message UDP pour " + recipient + " enregistré.");
                socket.send(Buffer.buffer("Message bien recu par le serveur !"), port, ip);
              });
            } else {
              System.out.println("⚠️  Destinataire UDP inconnu: " + recipient);
              socket.send(Buffer.buffer("Erreur : Destinataire inconnu."), port, ip);
            }
          });
        }
      });
    });

    // --- NETTOYAGE AUTO ---
    long MAX_AGE = 30 * 1000L;
    vertx.setPeriodic(10000, id -> {
      vertx.fileSystem().readDir("storage").onSuccess(users -> {
        for (String userPath : users) {
          String trashPath = userPath + "/trash";
          vertx.fileSystem().readDir(trashPath).onSuccess(files -> {
            for (String filePath : files) {
              vertx.fileSystem().props(filePath).onSuccess(props -> {
                long fileAge = System.currentTimeMillis() - props.lastModifiedTime();
                if (fileAge > MAX_AGE) {
                  vertx.fileSystem().delete(filePath).onSuccess(v -> {
                    System.out.println("🧹 Nettoyage auto : " + filePath + " supprimé.");
                  });
                }
              });
            }
          }).onFailure(err -> {});
        }
      }).onFailure(err -> {});
    });

    // ============================================
    // === DÉMARRAGE DU SERVEUR AVEC PORT DYNAMIQUE ===
    // ============================================

    int port = 8080; // CHANGEMENT DE PORT ICI (8888 -> 8080)
    if (System.getenv("PORT") != null) {
      try {
        port = Integer.parseInt(System.getenv("PORT"));
      } catch (NumberFormatException e) {
        System.err.println("Port invalide, retour au 8080");
      }
    }

    int finalPort = port;

    vertx.createHttpServer()
      .requestHandler(router)
      .listen(finalPort)
      .onSuccess(s -> {
        startPromise.complete();
        System.out.println("✅ Serveur Web démarré sur le port " + finalPort);
        if (finalPort == 8080) {
          System.out.println("➡️  Lien local : http://localhost:8080");
        }
      })
      .onFailure(err -> {
        System.err.println("❌ ECHEC DU DEMARRAGE DU SERVEUR !");
        System.err.println("Cause : " + err.getMessage());
        err.printStackTrace();
        startPromise.fail(err);
      });
  }

  // Méthode utilitaire pour compter les messages non lus
  private Future<Long> countUnread(String username) {
      String inboxPath = "storage/" + username + "/inbox";
      return vertx.fileSystem().readDir(inboxPath).compose(files -> {
          List<Future<Boolean>> checks = new ArrayList<>();
          for (String path : files) {
              checks.add(vertx.fileSystem().readFile(path).map(buf -> {
                  try {
                      return !new JsonObject(buf).getBoolean("isRead", false);
                  } catch (Exception e) { return false; }
              }));
          }
          return Future.all(checks).map(composite -> {
              long count = 0;
              for (int i = 0; i < composite.size(); i++) {
                  if (composite.resultAt(i)) count++;
              }
              return count;
          });
      }).recover(err -> Future.succeededFuture(0L));
  }

  private String hashPassword(String password) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] encodedhash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
      StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
      for (byte b : encodedhash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) hexString.append('0');
        hexString.append(hex);
      }
      return hexString.toString();
    } catch (Exception e) { throw new RuntimeException(e); }
  }

  // --- MAIN METHOD (Point d'entrée de l'application) ---
  public static void main(String[] args) {
    io.vertx.core.Vertx.vertx().deployVerticle(new MainVerticle());
  }
}
