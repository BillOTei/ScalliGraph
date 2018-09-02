ScalliGraph is a framework for web applications using graph database.

# Goals and features
 - Reduce boilerplate code as much as possible.
 - [gremlin](https://tinkerpop.apache.org/gremlin.html) DSL is used to access
 the database. Application doesn't require code specific to the database
 engine. 
 - type safe
 - Database schema generation
 - GraphQL
 
# How to use scalligraph

### Add Scalligraph in your build dependency
Currently, there is no official release of ScalliGraph. You can wait the first
release and add the dependency in your build file:
```
libraryDependencies += "org.thehive-project" %% "scalligraph" % "0.1.0"
```
or use ScalliGraph sources in your project:
```scala
lazy val scalligraph = (project in file("path/to/scalligraph"))
  .settings(name := "scalligraph")
lazy val myApplication = (project in file("."))
  .dependsOn(scalligraph)
```
ScalliGraph uses macros to reduce boilerplate code. The [macro paradise
compiler plugins](https://docs.scala-lang.org/overviews/macros/paradise.html)
must be enabled:
```scala
addCompilerPlugin("org.scalamacros" % "paradise" % "2.1.0" cross CrossVersion.full)
```

### Define your data model
Database schema is done by defining case classes and by annotate them with
`@VertexEntity` for vertex or `@EdgeEntity[From, To]` for edge. ScalliGraph
inspects these classes and generate database schema and CRUD methods.

```scala
import org.thp.scalligraph.models.{EdgeEntity, VertexEntity}

@VertexEntity
case class Person(name: String, age: Int)

@VertexEntity
case class Software(name: String, lang: String)

@EdgeEntity[Person, Person]
case class Knows(weight: Double)

@EdgeEntity[Person, Software]
case class Created(weight: Double)
```

The recognized types for model fields are `String`, `Long`, `Int`, `Date`,
`Boolean`, `Double`, `Float` and `JsObject`. Field can be `Option` and `Seq`
of theses types.

If it is not enough, you can create your own mapping by add implicit `UniMapping`
value of annotate the field with `@WithMapping`

### Define your service layer
For each entity (vertex and edge) you may have a service class that defines
what you can do with: CRUD. It also has a traversal to query your entities
using Gremlin DSL.

Default service class already defines these methods. You can of course override
them.
```scala
class PersonSrv(implicit db: Database) extends VertexSrv[Person] {
  // Add business operations on Person 
  override def steps(implicit graph: Graph): PersonSteps = new PersonSteps(graph.V.hasLabel(model.label))
}
```
Create method accepts model class and returns the same class with `Entity`
trait. This trait contains meta data, common to persisted vertex and edge:
`_id`, `_createdAt`, `_createdBy`, `_updatedAt`, `_updatedBy`.

The `steps` method returns a Gremlin traversal which can be enriched.
ScalliGrah uses gremlin-scala. You can have more details on how to write query
on gremlin-scala [home page](https://github.com/mpollmeier/gremlin-scala).
```scala
@EntitySteps[Person]
class PersonSteps(raw: GremlinScala[Vertex])(implicit db: Database) extends BaseVertexSteps[Person, PersonSteps](raw) {
  def created = new SoftwareSteps(raw.out("Created"))

  def knownPerson: List[Person] = raw.out("Knows").toList
}
```

With the annotation `@EntitySteps`, ScalliGraph add a method for each field of
your model which returns a traversal of that field value.
`personSteps.age.max.head` returns the age of the oldest person.
 
### Create your controllers
A controller method consists of extracting data from HTTP request, check user
permissions, call service layer and marshall the result.

ScalliGraph offers DSL to build a controller:
```scala
  apiMethod("create a person")
    .extract('person, FieldsParser[Person]) // Extract person from HTTP request
    .extract('friends, FieldsParser[String].sequence.on("friends")) // Extract a string under the name "friends"
    .requires(Permissions.write) { implicit request ⇒ // Check user authentication and verify if (s)he has the write permission
      // request is the HTTP request (play.api.mvc.Request) with authentication information (AuthContext)
      
      db.transaction { implicit graph ⇒ // Start a new transaction
        val person  = request.body('person) // retrive the extracted data from the HTTP request
        // Note that the type of person is the case class Person
        val friends = request.body('friends) // Seq[String]
        val createdPerson = personSrv.create(person)
        friends
          .map(personSrv.get) // get person from id
          .foreach(person ⇒ knowsSrv.create(Knows(1), createdPerson, person)) // then create edges 
        Results.Created
      }
    }
``` 

More details will come ...

### Query controller
Data is requested using 

### GraphQL