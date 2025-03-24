---
title: "Non-relational (NoSQL)"
date: 2025-03-07
draft: false
description: "a description"
tags: ["database", "web", "info"]
categories: ["Ethical Hacking", "Information"]
---
- A [non-relational database](https://en.wikipedia.org/wiki/NoSQL) does not use tables, rows, columns, primary keys, relationships, or schemas. Instead, a `NoSQL` database stores data using various storage models, depending on the type of data stored.

- Due to the lack of a defined structure for the database, `NoSQL` databases are very scalable and flexible. When dealing with datasets that are not very well defined and structured, a `NoSQL` database would be the best choice for storing our data.

- There are 4 common storage models for `NoSQL` databases:

	- Key-Value
	- Document-Based
	- Wide-Column
	- Graph

- Each of the above models has a different way of storing data. For example, the `Key-Value` model usually stores data in `JSON` or `XML`, and has a key for each pair, storing all of its data as its value:

{{< mermaid >}}

graph LR
    subgraph Posts 
        box1[id<br>date<br>content]
        box2[id<br>date<br>content]
        box3[id<br>date<br>content]
    end

    box1 --> Key1[Key]
    box1 --> Value1[Value]

    box2 --> Key2[Key]
    box2 --> Value2[Value]

    box3 --> Key3[Key]
    box3 --> Value3[Value]

{{< /mermaid >}}
- The above example can be represented using `JSON` as follows:

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

- It looks similar to a dictionary/map/key-value pair in languages like `Python` or `PHP` 'i.e. `{'key':'value'}`', where the `key` is usually a string, the `value` can be a string, dictionary, or any class object.

- The `Document-Based` model stores data in complex `JSON` objects and each object has certain meta-data while storing the rest of the data similarly to the `Key-Value` model.

- Some of the most common `NoSQL` databases include:

|Type|Description|
|---|---|
|[MongoDB](https://en.wikipedia.org/wiki/MongoDB)|The most common `NoSQL` database. It is free and open-source, uses the `Document-Based` model, and stores data in `JSON` objects|
|[ElasticSearch](https://en.wikipedia.org/wiki/Elasticsearch)|Another free and open-source `NoSQL` database. It is optimized for storing and analyzing huge datasets. As its name suggests, searching for data within this database is very fast and efficient|
|[Apache Cassandra](https://en.wikipedia.org/wiki/Apache_Cassandra)|Also free and open-source. It is very scalable and is optimized for gracefully handling faulty values|

- Other common `NoSQL` databases include: `Redis`, `Neo4j`, `CouchDB`, and `Amazon DynamoDB`.

