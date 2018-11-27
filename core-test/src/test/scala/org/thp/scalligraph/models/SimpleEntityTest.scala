package org.thp.scalligraph.models

import gremlin.scala.{Graph, GremlinScala, Vertex}
import play.api.{Configuration, Environment}
import play.api.libs.logback.LogbackLoggerConfigurator
import org.specs2.mock.Mockito
import org.specs2.specification.core.Fragments
import org.thp.scalligraph.VertexEntity
import org.thp.scalligraph.auth.{AuthContext, UserSrv}
import org.thp.scalligraph.services.VertexSrv
import play.api.test.PlaySpecification

@VertexEntity
case class MyEntity(name: String, value: Int)

object MyEntity {
  val initialValues = Seq(MyEntity("ini1", 1), MyEntity("ini1", 2))
}

class SimpleEntityTest extends PlaySpecification with Mockito {

  val userSrv: UserSrv                  = DummyUserSrv()
  implicit val authContext: AuthContext = userSrv.initialAuthContext
  (new LogbackLoggerConfigurator).configure(Environment.simple(), Configuration.empty, Map.empty)

  Fragments.foreach(new DatabaseProviders().list) { dbProvider ⇒
    implicit val db: Database = dbProvider.get()
    db.createSchema(db.getModel[MyEntity])
    val myEntitySrv: VertexSrv[MyEntity, VertexSteps[MyEntity]] = new VertexSrv[MyEntity, VertexSteps[MyEntity]] {
      override def steps(raw: GremlinScala[Vertex])(implicit graph: Graph): VertexSteps[MyEntity] = new VertexSteps[MyEntity](raw)
    }

    s"[${dbProvider.name}] simple entity" should {
      "create" in db.transaction { implicit graph ⇒
        val createdEntity: MyEntity with Entity = myEntitySrv.create(MyEntity("The answer", 42))
        createdEntity._id must_!== null
      }

      "create and get entities" in db.transaction { implicit graph ⇒
        val createdEntity: MyEntity with Entity = myEntitySrv.create(MyEntity("e^π", -1))
        val e                                   = myEntitySrv.getOrFail(createdEntity._id)
        e.name must_=== "e^π"
        e.value must_=== -1
        e._createdBy must_=== "test"
      }

      "update an entity" in db.transaction { implicit graph ⇒
        val id = myEntitySrv.create(MyEntity("super", 7))._id
        myEntitySrv.update(id, "value", 8)

        myEntitySrv.getOrFail(id).value must_=== 8
      }
    }
  }
}
