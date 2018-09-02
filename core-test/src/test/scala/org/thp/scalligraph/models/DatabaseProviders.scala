package org.thp.scalligraph.models

import javax.inject.Provider
import org.thp.scalligraph.janus.JanusDatabase
import org.thp.scalligraph.neo4j.Neo4jDatabase
import org.thp.scalligraph.orientdb.OrientDatabase
import play.api.Logger

object DatabaseProviders {
  lazy val logger = Logger(getClass)

  lazy val janus: DatabaseProvider = new DatabaseProvider("janus", new JanusDatabase)

  lazy val orientdb: DatabaseProvider = new DatabaseProvider("orientdb", new OrientDatabase)

  lazy val neo4j: DatabaseProvider = new DatabaseProvider("neo4j", new Neo4jDatabase)

  lazy val list: Seq[DatabaseProvider] = janus :: orientdb :: neo4j :: Nil
}

class DatabaseProvider(val name: String, db: ⇒ Database) extends Provider[Database] {
  private lazy val _db = new HookableDatabase(db)

  override def get(): Database = _db

  def asHookable: Provider[HookableDatabase] = this.asInstanceOf[Provider[HookableDatabase]]
}
