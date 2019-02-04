import sbt._

object Dependencies {
  lazy val gremlinScala                   = "com.michaelpollmeier"     %% "gremlin-scala"              % "3.3.4.14"
  lazy val gremlinOrientdb                = "com.orientechnologies"    % "orientdb-gremlin"            % "3.1.0-M2"
  lazy val janusGraph                     = "org.janusgraph"           % "janusgraph-core"             % "0.3.1"
  lazy val janusGraphBerkeleyDB           = "org.janusgraph"           % "janusgraph-berkeleyje"       % "0.3.1"
  lazy val scalactic                      = "org.scalactic"            %% "scalactic"                  % "3.0.5"
  lazy val specs                          = "com.typesafe.play"        %% "play-specs2"                % play.core.PlayVersion.current
  lazy val scalaGuice                     = "net.codingwell"           %% "scala-guice"                % "4.2.2"
  lazy val sangria                        = "org.sangria-graphql"      %% "sangria"                    % "1.4.2"
  lazy val sangriaPlay                    = "org.sangria-graphql"      %% "sangria-play-json"          % "1.0.5"
  lazy val shapeless                      = "com.chuusai"              %% "shapeless"                  % "2.3.3"
  lazy val bouncyCastle                   = "org.bouncycastle"         % "bcprov-jdk15on"              % "1.58"
  lazy val neo4jGremlin                   = "org.apache.tinkerpop"     % "neo4j-gremlin"               % "3.3.4"
  lazy val neo4jTinkerpop                 = "org.neo4j"                % "neo4j-tinkerpop-api-impl"    % "0.7-3.2.3" exclude ("org.slf4j", "slf4j-nop")
  lazy val arangodbTinkerpop              = "org.arangodb"             % "arangodb-tinkerpop-provider" % "2.0.1"
  lazy val apacheConfiguration            = "commons-configuration"    % "commons-configuration"       % "1.10"
  lazy val macroParadise                  = "org.scalamacros"          % "paradise"                    % "2.1.1" cross CrossVersion.full
  lazy val playLogback                    = "com.typesafe.play"        %% "play-logback"               % play.core.PlayVersion.current
  lazy val playGuice                      = "com.typesafe.play"        %% "play-guice"                 % play.core.PlayVersion.current
  lazy val chimney                        = "io.scalaland"             %% "chimney"                    % "0.3.0"
  lazy val elastic4play                   = "org.thehive-project"      %% "elastic4play"               % "1.7.2" /*exclude ("org.apache.logging.log4j", "log4j-core") exclude("org.apache.logging.log4j", "log4j-api") exclude("org.apache.logging.log4j", "log4j-1.2-api") */
  lazy val log4jOverSlf4j                 = "org.slf4j"                % "log4j-over-slf4j"            % "1.7.25"
  lazy val log4jToSlf4j                   = "org.apache.logging.log4j" % "log4j-to-slf4j"              % "2.9.1"
  lazy val reflections                    = "org.reflections"          % "reflections"                 % "0.9.11"
  def scalaReflect(scalaVersion: String)  = "org.scala-lang"           % "scala-reflect"               % scalaVersion
  def scalaCompiler(scalaVersion: String) = "org.scala-lang"           % "scala-compiler"              % scalaVersion
}
