package com.projetmessagerie.vertimail;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.datagram.DatagramSocket;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.FileUpload;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import io.vertx.ext.web.templ.pebble.PebbleTemplateEngine;

import java.io.File;
import java.io.FileInputStream;
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

  // Durées de session (en millisecondes)
  private static final long SESSION_TIMEOUT_DEFAULT = 30 * 60 * 1000L; // 30 minutes

  @Override
  public void start(Promise<Void> startPromise) throws Exception {
    System.out.println("🚀 Démarrage de l'application...");

    engine = PebbleTemplateEngine.create(vertx);
    Router router = Router.router(vertx);

    // 1. Activer le BodyHandler pour lire les formulaires et les uploads
    // On configure un dossier temporaire pour les uploads
    router.route().handler(BodyHandler.create().setUploadsDirectory("file-uploads"));

    // 2. Activer les Sessions
    SessionHandler sessionHandler = SessionHandler.create(LocalSessionStore.create(vertx))
            .setSessionTimeout(SESSION_TIMEOUT_DEFAULT);
    router.route().handler(sessionHandler);

    // Créer le dossier de stockage des pièces jointes s'il n'existe pas
    vertx.fileSystem().mkdirs("storage/attachments");

    // --- ROUTE CSS ---
    router.get("/style.css").handler(ctx -> {
      vertx.fileSystem().readFile("src/main/resources/style.css")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/css").end(buffer))
        .onFailure(err -> ctx.response().sendFile("style.css"));
    });

    // --- ROUTES PUBLIQUES ---

    router.get("/").handler(ctx -> {
      if (ctx.session().get("user") != null) {
          ctx.redirect("/box");
          return;
      }
      io.vertx.core.http.Cookie rememberCookie = ctx.request().getCookie("remember_user");
      if (rememberCookie != null) {
          String user = rememberCookie.getValue();
          ctx.session().put("user", user);
          ctx.redirect("/box");
          return;
      }
      String success = ctx.request().getParam("success");
      if (success != null && success.equals("created")) {
          ctx.put("success", "Compte créé avec succès ! Connectez-vous.");
      } else if (success != null && success.equals("reset")) {
          ctx.put("success", "Mot de passe réinitialisé avec succès !");
      }
      engine.render(ctx.data(), "templates/login.peb")
        .onSuccess(buffer -> ctx.response().putHeader("content-type", "text/html").end(buffer));
    });

    router.get("/register").handler(ctx -> {
      if (ctx.session().get("user") != null) {
          ctx.redirect("/box");
          return;
      }
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

        if (!password.equals(confirmPassword)) {
            ctx.response().end("Erreur : Les mots de passe ne correspondent pas.");
            return;
        }

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
                        .onSuccess(vv -> ctx.redirect("/?success=created"));
                });
            }
        });
    });

    router.post("/login").handler(ctx -> {
      String username = ctx.request().getFormAttribute("username");
      String password = ctx.request().getFormAttribute("password");
      String rememberMe = ctx.request().getFormAttribute("remember");
      String hashPath = "storage/" + username + "/password.hash";

      vertx.fileSystem().exists(hashPath).onSuccess(exists -> {
        if (!exists) {
          ctx.put("error", "Compte inexistant.");
          engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
        } else {
          vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
            if (buffer.toString().equals(hashPassword(password))) {
              ctx.session().put("user", username);
              if (rememberMe != null && rememberMe.equals("on")) {
                  ctx.response().addCookie(io.vertx.core.http.Cookie.cookie("remember_user", username)
                          .setMaxAge(30L * 24 * 60 * 60)
                          .setPath("/")
                          .setHttpOnly(true));
              }
              ctx.redirect("/box");
            } else {
              ctx.put("error", "Mot de passe faux.");
              engine.render(ctx.data(), "templates/login.peb").onSuccess(buf -> ctx.response().end(buf));
            }
          });
        }
      });
    });

    // --- ROUTES MOT DE PASSE OUBLIÉ ---

    router.get("/forgot-password").handler(ctx -> {
        engine.render(ctx.data(), "templates/forgot-password.peb")
            .onSuccess(buf -> ctx.response().putHeader("content-type", "text/html").end(buf));
    });

    router.post("/forgot-password").handler(ctx -> {
        String username = ctx.request().getFormAttribute("username");
        String userPath = "storage/" + username;

        vertx.fileSystem().exists(userPath).onSuccess(exists -> {
            if (exists) {
                ctx.redirect("/reset-password?username=" + username);
            } else {
                ctx.put("error", "Utilisateur introuvable.");
                engine.render(ctx.data(), "templates/forgot-password.peb").onSuccess(buf -> ctx.response().end(buf));
            }
        });
    });

    router.get("/reset-password").handler(ctx -> {
        String username = ctx.request().getParam("username");
        if (username == null) {
            ctx.redirect("/forgot-password");
            return;
        }
        ctx.put("username", username);
        engine.render(ctx.data(), "templates/reset-password.peb")
            .onSuccess(buf -> ctx.response().putHeader("content-type", "text/html").end(buf));
    });

    router.post("/reset-password").handler(ctx -> {
        String username = ctx.request().getFormAttribute("username");
        String newPassword = ctx.request().getFormAttribute("newPassword");
        String confirmPassword = ctx.request().getFormAttribute("confirmPassword");

        ctx.put("username", username);

        if (!newPassword.equals(confirmPassword)) {
            ctx.put("error", "Les mots de passe ne correspondent pas.");
            engine.render(ctx.data(), "templates/reset-password.peb").onSuccess(buf -> ctx.response().end(buf));
            return;
        }

        if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
            ctx.put("error", "Le mot de passe ne respecte pas les critères de sécurité.");
            engine.render(ctx.data(), "templates/reset-password.peb").onSuccess(buf -> ctx.response().end(buf));
            return;
        }

        String hashPath = "storage/" + username + "/password.hash";
        String newHash = hashPassword(newPassword);

        vertx.fileSystem().writeFile(hashPath, Buffer.buffer(newHash)).onSuccess(v -> {
            ctx.redirect("/?success=reset");
        }).onFailure(err -> {
            ctx.put("error", "Erreur lors de la mise à jour.");
            engine.render(ctx.data(), "templates/reset-password.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    // Route de déconnexion
    router.get("/logout").handler(ctx -> {
        ctx.session().destroy();
        ctx.response().addCookie(io.vertx.core.http.Cookie.cookie("remember_user", "")
                .setMaxAge(0)
                .setPath("/"));
        ctx.redirect("/");
    });

    // --- MIDDLEWARE D'AUTHENTIFICATION ---
    router.route().handler(ctx -> {
        String path = ctx.request().path();
        if (path.startsWith("/api/") || path.startsWith("/attachment/") || path.equals("/") || path.equals("/login") || path.equals("/register") || path.equals("/style.css") || path.equals("/forgot-password") || path.equals("/reset-password")) {
            ctx.next();
            return;
        }

        if (ctx.session().get("user") != null) {
            ctx.next();
            return;
        }

        io.vertx.core.http.Cookie rememberCookie = ctx.request().getCookie("remember_user");
        if (rememberCookie != null) {
            String user = rememberCookie.getValue();
            ctx.session().put("user", user);
            ctx.next();
        } else {
            ctx.redirect("/");
        }
    });

    // --- ROUTES PROTEGEES ---

    // Route pour basculer le statut "Important"
    router.post("/toggle-important").handler(ctx -> {
        String username = ctx.session().get("user");
        String folder = ctx.request().getFormAttribute("folder");
        String filename = ctx.request().getFormAttribute("filename");

        if (username == null || folder == null || filename == null) {
            ctx.redirect("/box");
            return;
        }

        String path = "storage/" + username + "/" + folder + "/" + filename;

        vertx.fileSystem().readFile(path)
            .compose(buffer -> {
                JsonObject mail = new JsonObject(buffer);
                boolean isImportant = mail.getBoolean("isImportant", false);
                mail.put("isImportant", !isImportant); // On inverse
                return vertx.fileSystem().writeFile(path, mail.toBuffer());
            })
            .onSuccess(v -> ctx.redirect("/box?folder=" + folder))
            .onFailure(err -> ctx.redirect("/box?folder=" + folder));
    });

    router.get("/settings").handler(ctx -> {
        String user = ctx.session().get("user");
        ctx.put("username", user);

        countUnread(user).onSuccess(count -> {
            ctx.put("unreadCount", count);
            engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
        }).onFailure(err -> {
            ctx.put("unreadCount", 0);
            engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    router.post("/settings/password").handler(ctx -> {
        String user = ctx.session().get("user");
        String oldPassword = ctx.request().getFormAttribute("oldPassword");
        String newPassword = ctx.request().getFormAttribute("newPassword");
        String confirmPassword = ctx.request().getFormAttribute("confirmPassword");

        ctx.put("username", user);

        countUnread(user).onSuccess(count -> ctx.put("unreadCount", count)).onFailure(err -> ctx.put("unreadCount", 0));

        if (oldPassword == null || newPassword == null || confirmPassword == null) {
            ctx.put("error", "Tous les champs sont obligatoires.");
            engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
            return;
        }

        if (!newPassword.equals(confirmPassword)) {
            ctx.put("error", "Les nouveaux mots de passe ne correspondent pas.");
            engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
            return;
        }

        if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
            ctx.put("error", "Le nouveau mot de passe ne respecte pas les critères de sécurité.");
            engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
            return;
        }

        String hashPath = "storage/" + user + "/password.hash";

        vertx.fileSystem().readFile(hashPath).onSuccess(buffer -> {
            if (buffer.toString().equals(hashPassword(oldPassword))) {
                String newHash = hashPassword(newPassword);
                vertx.fileSystem().writeFile(hashPath, Buffer.buffer(newHash)).onSuccess(v -> {
                    ctx.put("success", "Mot de passe modifié avec succès !");
                    engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
                });
            } else {
                ctx.put("error", "Ancien mot de passe incorrect.");
                engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
            }
        }).onFailure(err -> {
            ctx.put("error", "Erreur système.");
            engine.render(ctx.data(), "templates/settings.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    router.get("/compose").handler(ctx -> {
        String user = ctx.session().get("user");
        String recipient = ctx.request().getParam("recipient");
        String subject = ctx.request().getParam("subject");

        ctx.put("username", user);
        if (recipient != null) ctx.put("recipient", recipient);
        if (subject != null) ctx.put("subject", subject);

        countUnread(user).onSuccess(count -> {
            ctx.put("unreadCount", count);
            engine.render(ctx.data(), "templates/compose.peb").onSuccess(buf -> ctx.response().end(buf));
        }).onFailure(err -> {
            ctx.put("unreadCount", 0);
            engine.render(ctx.data(), "templates/compose.peb").onSuccess(buf -> ctx.response().end(buf));
        });
    });

    router.post("/send").handler(ctx -> {
      String sender = ctx.session().get("user");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      String content = ctx.request().getFormAttribute("content");
      List<FileUpload> uploads = ctx.fileUploads();

      // Traitement des pièces jointes
      List<Future<JsonObject>> attachmentFutures = new ArrayList<>();
      for (FileUpload upload : uploads) {
          // Utilisation de la syntaxe compatible Vert.x 4/5 pour executeBlocking
          attachmentFutures.add(vertx.executeBlocking(() -> {
              try {
                  String hash = calculateSHA256(upload.uploadedFileName());
                  String targetPath = "storage/attachments/" + hash;

                  if (!new File(targetPath).exists()) {
                      new File(upload.uploadedFileName()).renameTo(new File(targetPath));
                  } else {
                      new File(upload.uploadedFileName()).delete();
                  }

                  return new JsonObject()
                      .put("name", upload.fileName())
                      .put("hash", hash)
                      .put("size", upload.size())
                      .put("type", upload.contentType());
              } catch (Exception e) {
                  throw new RuntimeException(e);
              }
          }));
      }

      Future.all(attachmentFutures).onSuccess(composite -> {
          JsonArray attachments = new JsonArray();
          for (int i = 0; i < composite.size(); i++) {
              attachments.add(composite.resultAt(i));
          }

          JsonObject mail = new JsonObject()
            .put("from", sender)
            .put("to", recipient)
            .put("date", java.time.Instant.now().toString())
            .put("subject", subject)
            .put("content", content)
            .put("isRead", false)
            .put("attachments", attachments);

          String filename = System.currentTimeMillis() + ".json";
          vertx.fileSystem().writeFile("storage/" + recipient + "/inbox/" + filename, mail.toBuffer())
            .onSuccess(v -> {
                JsonObject outboxMail = mail.copy().put("isRead", true);
                vertx.fileSystem().writeFile("storage/" + sender + "/outbox/" + filename, outboxMail.toBuffer())
                  .onSuccess(v2 -> ctx.redirect("/box?folder=outbox"))
                  .onFailure(e -> ctx.response().end("Erreur outbox"));
            })
            .onFailure(e -> ctx.response().end("Erreur destinataire"));
      }).onFailure(err -> ctx.response().end("Erreur lors de l'upload des fichiers: " + err.getMessage()));
    });

    // Route pour télécharger une pièce jointe
    router.get("/attachment/:hash").handler(ctx -> {
        if (ctx.session().get("user") == null) {
            ctx.response().setStatusCode(403).end("Accès refusé");
            return;
        }

        String hash = ctx.request().getParam("hash");
        String name = ctx.request().getParam("name"); // On récupère le nom d'origine
        String path = "storage/attachments/" + hash;

        vertx.fileSystem().exists(path).onSuccess(exists -> {
            if (exists) {
                // On force le téléchargement avec le bon nom
                if (name != null) {
                    ctx.response().putHeader("Content-Disposition", "attachment; filename=\"" + name + "\"");
                }
                ctx.response().sendFile(path);
            } else {
                ctx.response().setStatusCode(404).end("Fichier introuvable");
            }
        });
    });

    router.post("/draft").handler(ctx -> {
      String sender = ctx.session().get("user");
      String content = ctx.request().getFormAttribute("content");
      String recipient = ctx.request().getFormAttribute("recipient");
      String subject = ctx.request().getFormAttribute("subject");
      JsonObject mail = new JsonObject().put("from", sender).put("to", recipient == null ? "" : recipient)
        .put("date", java.time.Instant.now().toString()).put("subject", subject).put("content", content);
      vertx.fileSystem().writeFile("storage/" + sender + "/draft/" + System.currentTimeMillis() + ".json", mail.toBuffer())
        .onSuccess(v -> ctx.redirect("/box?folder=draft"));
    });

    router.post("/delete").handler(ctx -> {
      String username = ctx.session().get("user");
      String folder = ctx.request().getFormAttribute("folder");
      String filename = ctx.request().getFormAttribute("filename");
      String path = "storage/" + username + "/" + folder + "/" + filename;
      if ("trash".equals(folder)) vertx.fileSystem().delete(path).onSuccess(v -> ctx.redirect("/box?folder=" + folder));
      else vertx.fileSystem().move(path, "storage/" + username + "/trash/" + filename).onSuccess(v -> ctx.redirect("/box?folder=" + folder));
    });

    router.get("/read").handler(ctx -> {
        String username = ctx.session().get("user");
        String folder = ctx.request().getParam("folder");
        String id = ctx.request().getParam("id");
        String path = "storage/" + username + "/" + folder + "/" + id;

        vertx.fileSystem().readFile(path)
            .compose(buffer -> {
                JsonObject mail = new JsonObject(buffer);
                if (mail.getBoolean("isRead", false) == false) {
                    mail.put("isRead", true);
                    return vertx.fileSystem().writeFile(path, mail.toBuffer())
                        .map(v -> mail);
                } else {
                    return Future.succeededFuture(mail);
                }
            })
            .compose(mail -> {
                return Future.all(countUnread(username), calculateUserSpace(username)).map(composite -> {
                    ctx.put("username", username)
                       .put("folder", folder)
                       .put("id", id)
                       .put("mail", mail)
                       .put("unreadCount", composite.resultAt(0))
                       .put("userSpace", composite.resultAt(1));
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
      String username = ctx.session().get("user");
      String folder = ctx.request().getParam("folder") == null ? "inbox" : ctx.request().getParam("folder");
      String query = ctx.request().getParam("q"); // Récupération du paramètre de recherche
      String folderPath = "storage/" + username + "/" + folder;
      final String currentFolder = folder;

      Future<List<JsonObject>> currentFolderFuture = vertx.fileSystem().readDir(folderPath).compose(files -> {
          List<JsonObject> mails = new ArrayList<>();
          Future<Void> chain = Future.succeededFuture();
          for (String path : files) {
              chain = chain.compose(v -> vertx.fileSystem().readFile(path).map(buf -> {
                  try {
                      JsonObject json = new JsonObject(buf);
                      json.put("id", new File(path).getName());

                      // FILTRAGE (Recherche)
                      if (query != null && !query.trim().isEmpty()) {
                          String q = query.toLowerCase();
                          boolean match = (json.getString("subject", "").toLowerCase().contains(q)) ||
                                          (json.getString("from", "").toLowerCase().contains(q)) ||
                                          (json.getString("to", "").toLowerCase().contains(q));
                          if (match) {
                              mails.add(json);
                          }
                      } else {
                          mails.add(json);
                      }
                  } catch (Exception e) {}
                  return null;
              }));
          }
          return chain.map(v -> mails);
      });

      Future<Long> unreadCountFuture = countUnread(username);
      Future<String> userSpaceFuture = calculateUserSpace(username);

      Future.all(currentFolderFuture, unreadCountFuture, userSpaceFuture).onSuccess(composite -> {
          List<JsonObject> mails = composite.resultAt(0);
          Long unreadCount = composite.resultAt(1);
          String userSpace = composite.resultAt(2);

          mails.sort((m1, m2) -> {
              String id1 = m1.getString("id");
              String id2 = m2.getString("id");
              return id2.compareTo(id1);
          });

          ctx.put("username", username)
             .put("mails", mails)
             .put("folder", currentFolder)
             .put("unreadCount", unreadCount)
             .put("userSpace", userSpace)
             .put("query", query);

          engine.render(ctx.data(), "templates/inbox.peb")
            .onSuccess(buf -> ctx.response().end(buf))
            .onFailure(err -> {
                err.printStackTrace();
                ctx.response().setStatusCode(500).end("Erreur d'affichage");
            });
      }).onFailure(err -> {
          ctx.put("username", username).put("mails", new ArrayList<>()).put("folder", currentFolder).put("unreadCount", 0).put("userSpace", "0 o");
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
            .put("isRead", false);

          String filename = System.currentTimeMillis() + ".json";
          String inboxPath = "storage/" + recipient + "/inbox/" + filename;
          String outboxPath = "storage/" + sender + "/outbox/" + filename;

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
      String folder = ctx.request().getParam("folder");

      if (username == null || folder == null) {
        ctx.json(new JsonObject().put("status", "error").put("message", "Manque username ou folder"));
        return;
      }

      String path = "storage/" + username + "/" + folder;

      vertx.fileSystem().exists(path).onSuccess(exists -> {
        if (exists) {
          vertx.fileSystem().readDir(path).onSuccess(files -> {
            List<JsonObject> mailList = new ArrayList<>();
            List<Future<Void>> futures = new ArrayList<>();

            for (String filePath : files) {
                Promise<Void> p = Promise.promise();
                futures.add(p.future());
                vertx.fileSystem().readFile(filePath).onSuccess(buffer -> {
                    try {
                        JsonObject mailJson = new JsonObject(buffer.toString());
                        mailJson.put("id", new File(filePath).getName());
                        synchronized(mailList) {
                            mailList.add(mailJson);
                        }
                    } catch (Exception e) {}
                    p.complete();
                }).onFailure(err -> p.complete());
            }

            Future.all(futures).onSuccess(v -> {
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
                mail.put("isRead", true);
                return vertx.fileSystem().writeFile(path, mail.toBuffer());
            })
            .onSuccess(v -> ctx.json(new JsonObject().put("status", "ok")))
            .onFailure(err -> ctx.json(new JsonObject().put("status", "error").put("message", err.getMessage())));
    });

    // --- NOUVELLE ROUTE POUR LES NOTIFICATIONS ---
    router.get("/api/notifications").handler(ctx -> {
        String username = ctx.request().getParam("username");
        if (username == null) {
            ctx.json(new JsonObject().put("status", "error").put("message", "Username manquant"));
            return;
        }

        String inboxPath = "storage/" + username + "/inbox";
        vertx.fileSystem().readDir(inboxPath).onSuccess(files -> {
            List<JsonObject> unreadMails = new ArrayList<>();
            List<Future<Void>> futures = new ArrayList<>();

            for (String path : files) {
                Promise<Void> p = Promise.promise();
                futures.add(p.future());
                vertx.fileSystem().readFile(path).onSuccess(buffer -> {
                    try {
                        JsonObject mail = new JsonObject(buffer);
                        if (!mail.getBoolean("isRead", false)) {
                            // On ne garde que l'essentiel pour la notif
                            JsonObject notif = new JsonObject()
                                .put("subject", mail.getString("subject"))
                                .put("from", mail.getString("from"));
                            synchronized(unreadMails) {
                                unreadMails.add(notif);
                            }
                        }
                    } catch (Exception e) {}
                    p.complete();
                }).onFailure(err -> p.complete());
            }

            Future.all(futures).onSuccess(v -> {
                ctx.json(new JsonObject().put("status", "ok").put("notifications", new JsonArray(unreadMails)));
            });
        }).onFailure(err -> {
            // Si le dossier n'existe pas ou erreur, on renvoie une liste vide
            ctx.json(new JsonObject().put("status", "ok").put("notifications", new JsonArray()));
        });
    });

    // --- SERVEUR UDP ---
    DatagramSocket socket = vertx.createDatagramSocket();
    socket.listen(9999, "0.0.0.0").onSuccess(so -> {
      System.out.println("👻 Serveur UDP anonyme écoute sur le port 9999 (Toutes interfaces)");
      socket.handler(packet -> {
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

          JsonObject mail = new JsonObject()
            .put("from", "Anonyme (" + packet.sender().host() + ")")
            .put("to", recipient)
            .put("date", java.time.Instant.now().toString())
            .put("subject", "[UDP] " + subject)
            .put("content", content)
            .put("isRead", false);

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

    int port = 8080;
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

  // Méthode pour calculer l'espace utilisé
  private Future<String> calculateUserSpace(String username) {
      String userPath = "storage/" + username;
      List<String> folders = List.of("inbox", "outbox", "draft", "trash");

      List<Future<Long>> futures = new ArrayList<>();

      for (String folder : folders) {
          String folderPath = userPath + "/" + folder;
          futures.add(vertx.fileSystem().readDir(folderPath).compose(files -> {
              List<Future<Long>> fileSizes = new ArrayList<>();
              for (String file : files) {
                  fileSizes.add(vertx.fileSystem().readFile(file).map(buf -> {
                      try {
                          JsonObject json = new JsonObject(buf);
                          long size = buf.length(); // Taille du JSON

                          // Ajouter la taille des pièces jointes
                          JsonArray attachments = json.getJsonArray("attachments");
                          if (attachments != null) {
                              for (int i = 0; i < attachments.size(); i++) {
                                  size += attachments.getJsonObject(i).getLong("size", 0L);
                              }
                          }
                          return size;
                      } catch (Exception e) { return 0L; }
                  }));
              }
              return Future.all(fileSizes).map(composite -> {
                  long total = 0;
                  for (int i = 0; i < composite.size(); i++) {
                      total += (Long) composite.resultAt(i);
                  }
                  return total;
              });
          }).recover(err -> Future.succeededFuture(0L)));
      }

      return Future.all(futures).map(composite -> {
          long totalBytes = 0;
          for (int i = 0; i < composite.size(); i++) {
              totalBytes += (Long) composite.resultAt(i);
          }

          // Formatage
          if (totalBytes < 1024) return totalBytes + " o";
          if (totalBytes < 1024 * 1024) return String.format("%.1f Ko", totalBytes / 1024.0);
          return String.format("%.1f Mo", totalBytes / (1024.0 * 1024.0));
      });
  }

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

  private String calculateSHA256(String filePath) throws Exception {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (FileInputStream fis = new FileInputStream(filePath)) {
          byte[] byteArray = new byte[1024];
          int bytesCount;
          while ((bytesCount = fis.read(byteArray)) != -1) {
              digest.update(byteArray, 0, bytesCount);
          }
      }
      byte[] bytes = digest.digest();
      StringBuilder sb = new StringBuilder();
      for (byte b : bytes) {
          sb.append(String.format("%02x", b));
      }
      return sb.toString();
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

  public static void main(String[] args) {
    io.vertx.core.Vertx.vertx().deployVerticle(new MainVerticle());
  }
}
