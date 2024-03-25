# Static analysis of microservices with LiSA #

**This document serves as a collection of research notes and thought processes on the topic of how to step-by-step apply and build a static code analyzer (via LiSA) to microservices.**

**Keywords**: `Static code analyzing`, `LiSA`, `Python`, `Microservices`

## Rough course of action ##

1. `On what the analyzer is targeting`. Prepare a list of issues, vulnerabilities, and code smells existing in microservices systems. 

2. `On how the LiSA analyzer could be extended`. Search and understand how LiSA as a base could be extended. Prepare an importable module that would help and instruct LiSA to work with some main Python microservice frameworks like Fast API, etc. Inspect examples like (lisa4ros2)[ https://github.com/lisa-analyzer/lisa4ros2]. Additionally, investigate how LiSA could consume and scan entire project folders (not just single files) built on the mentioned frameworks. 

3. `On the localization of the code of interest`. Frameworks provide a large set of solutions and syntaxis dedicated to the different concerns of services development, build-up, maintenance, and testing. Define a list of syntax examples that are associated with the point of communication. These would be the code portions that LiSA to later statically analyze.  

4. `On dissection of syntax`. Learn how to use SARL to decode framework syntax (annotations, declarations, etc.) and make them usable and understandable for further LiSA analysis pipeline.

5. `On results`. Specify what the results of a statically analyzed system of microservices should look like. In the context of issues and warnings investigate how LiSA checkers could output them textually. In the context of visualization investigate how LiSA’s current graph capabilities could accommodate visual representation of microservice provider-consumption edges. 

## 1. On what the analyzer is targeting

The specific of static code analysis in the field of microservices is a focus on inter-service issues and code smells, in other words on workflow problematics between two more microservices and their mutual communication or contact points. 

### Sources:

#### 1.	*Registries like OWASP, Common Weakness Enumeration (CWE), and NIST National Vulnerability DB.*

`Nuance with the mentioned registries is that there is no dedicated microservice category or tag in their search functionality.` Registries typically focus on individual vulnerabilities and weaknesses rather than systemic issues that arise specifically from the interactions between microservices. Only a bit of extra work and widening some of the individual issues could be transformed into an inter-service one. For example:

**Improper Validation of Specified Type of Input (CWE-1287)**

`Description`: The product receives input that is expected to be of a certain type, but it does not validate or incorrectly validates that the input is actually of the expected type.

`Extension`: From such issues that by nature are solitary, it is **possible to derive and formulate** that in the system of microservices when the object is transferred from one to another their common fields must be in the same type of declaration.

Some more:

**Implicit Conversion (CWE- 690)**

`Description`: The system performs implicit conversion of data types, leading to potential unexpected behavior or vulnerabilities.

`Extension`: Microservices should avoid relying on implicit conversions between data types, as they can lead to unexpected behavior or vulnerabilities during data exchange.

**Incorrect Conversion between Numeric Types (CWE-681)**

`Description`: When converting from one data type to another, such as long to integer, data can be omitted or translated in a way that produces unexpected values. If the resulting values are used in a sensitive context, then dangerous behaviors may occur.

`Extension`: Discourage valid, but implicit numeric conversions like long to integer or double to float between microservices.

**Assignment to Variable without Use (CWE-563)**

`Description`: The variable's value is assigned but never used, making it a dead store.

`Extension`: Microservice provides an object in the response body where certain fields are not used in any other microservice that calls or consumes it.

**Unchecked Return Value (CWE-252)**

`Description`: The variable's value is assigned but never used, making it a dead store.

`Extension`: Remove endpoints that are not used by any other microservice in the system.

**Uncontrolled Resource Consumption (CWE-400)**

`Description`: The system does not properly limit resource consumption, leading to denial of service or performance degradation.

`Extension`: Microservices should implement controls to limit resource consumption, preventing individual services from consuming excessive resources and affecting the overall system performance.

**Exposure of Sensitive Information to an Unauthorized Actor (CWE-200)**

`Description`: The system exposes sensitive information to unauthorized actors, leading to data breaches or privacy violations.

`Extension`: Microservices should delegate which resource is accessible to which microservice in the system.

**Unrestricted File Upload (CWE-434)**

`Description`: The system allows users to upload files without proper validation or enforcement of file types, leading to potential file upload vulnerabilities and execution of malicious code.

`Extension`: Microservices should implement strict file upload validation and enforce restrictions on allowed file types and sizes that are coming from neighboring microservices.

**Insufficient Logging and Monitoring (CWE-798)**

`Description`: The system lacks sufficient logging and monitoring capabilities, hindering detection and response to security incidents or suspicious activities.

`Extension`: Microservice is handling a resource without any logging that comes from neighboring microservice where such logging is present. This loses resource trace path and procedure history. 

**Unprotected Transport of Credentials (CWE-523)**

`Description`: Login pages do not use adequate measures to protect the user name and password while they are in transit from the client to the server.

`Extension`: In a microservices architecture, where communication between services is prevalent, a system may establish a network of trusted entities for inter-service communication. However, even within this trusted environment, it remains essential to encode or encrypt credentials during transmission. Implementing secure transport protocols such as HTTPS or utilizing encryption mechanisms ensures that sensitive credentials are adequately protected, mitigating the risk of interception and unauthorized access, thereby maintaining the integrity and security of the system.

### 2.	Trivial issues.

Considerable parts of potential issues are trivial ones. For example:

1.Ensure that both microservices adhere to consistent naming conventions for variables, functions, endpoints, and other elements. E.g. both microservices communicate with identical field names, disallowing any variation like `studentId` from one side and `student_id` from the other.

2.Verify that both microservices use standardized date and time formats across API responses and database interactions. Check if all microservices in the same system have explicit time and date configurations and no time zone misalignment. 

3.Ensure that both microservices enforce the Content-Type header for incoming requests, requiring clients to specify the type of data being sent. 

4.Verify that operations exposed by both microservices are idempotent when appropriate, meaning that executing the operation multiple times has the same effect as executing it once. 

5.Verify that there is no HTTP request misalignment. For example, there is no GET request to the endpoint that accepts POST requests, etc. 

6.Check that both microservices handle timeouts gracefully when communicating with other services or resources. Handling timeouts ensures that the system remains responsive and resilient under adverse conditions.

7.Check adherence to standards, like HTTP GET requests should not have a body payload. 

8.Check if the requests to the secured endpoints supply authorization parameters. 

9.Evaluate that if passed objects or parameters are valid at least at the entry-level (i.e. passes validation specified in the REST controller). 

10.Check that endpoint names follow a consistent naming convention across both microservices. Consistent naming conventions improve clarity and ease of understanding, facilitating collaboration among developers and API consumers. An endpoint that is defined all in a small case should not be accessed with the same letters, but in Caps Lock. 

11.Handling of Optional Parameters. Verify that both microservices handle optional parameters consistently, including how they interpret and process requests with missing or incomplete parameters. Consistent handling of optional parameters enhances interoperability and prevents unexpected behavior.

12.Ensure that error messages returned by both microservices follow a standardized format and language. Consistent error messages improve clarity and help quickly identify and troubleshoot issues.

### 3.	Researching best practices, known challenges, and potential risks from industry literature.

Researching best practices, known challenges, and potential risks from industry literature.

1.**Dependency Drift**: Lack of proper dependency management and versioning practices can lead to dependency drift, where microservices use different versions of shared libraries or frameworks, potentially introducing compatibility issues and security vulnerabilities.

2.**Lack of Trace Context Propagation**: Inconsistent or inadequate propagation of trace context between microservices can hinder effective distributed tracing, making it challenging to debug and analyze system behavior.

3.**Single Point of Failure**: API gateways can become single points of failure, leading to service disruptions for all microservices behind them.

4.**Distributed Transactions**: Lack of support for distributed transactions can result in inconsistencies across microservices' data stores.

5.**Consistent Authentication Mechanisms**: Ensure that both microservices use consistent authentication mechanisms across endpoints, such as token-based authentication or OAuth, and not both of them. 

### 4.	*Investigating issues available in academic sources.*

Academic papers that present their static code analysis tool or solution contain information about issues and code smells that they are resolving. Andrew Walker et al. paper where the static analysis tool MSANose is presented has supplemented with the identification of eleven code smells. 

**ESB Usage**: An Enterprise Service Bus (ESB) [2] is a way of message passing between modules of a distributed application in which one module acts as a service bus for all of the other modules to pass messages on. There are pros and cons to this approach. However, in microservices, it can become an issue of creating a single point of failure, and increasing coupling, so it should be avoided. 

**Too Many Standards**: Given the distributed nature of the microservice application, multiple discrete teams of developers often work on a given module, separate from the other teams. This can create a situation where multiple frameworks are used when a standard should be established for consistency across the modules.

**Wrong Cuts**: This occurs when microservices are split into their technical layers (presentation, business, and data layers). Microservices are supposed to be split by features, and each fully contains their domain’s presentation, business, and data layers.

**Not Having an API Gateway**: The API gateway pattern is a design pattern for managing the connections between microservices. In large, complex systems, this should be used to reduce the potential issues of direct communication.

**Hard-Coded Endpoints**: Hardcoded IP addresses and ports are used to communicate between services. By hardcoding the endpoints, the application becomes more brittle to change and reduces the application’s scalability.

**API Versioning**: All Application Programming Interfaces (API) should be versioned to keep track of changes properly.

**Microservice Greedy**: This occurs when microservices are created for every new feature, and, oftentimes, these new modules are too small and do not serve many purposes. This increases complexity and the overhead of the system. Smaller features should be wrapped into larger microservices if possible.

**Shared Persistency**: When two microservice application modules access the same database, it breaks the microservice definition. Each microservice should have autonomy and control over its data and database. 

**Inappropriate Service Intimacy**: One module requesting private data from a separate module also breaks the microservice definition. Each microservice should have control over its private data.

**Shared Libraries**: If microservices are coupled with a common library, that library should be refactored into a separate module. This reduces the fragility of the application by migrating the shared functionality behind a common, unchanging interface. This will make the system resistant to ripples from changes within the library.

**Cyclic Dependency**: This occurs when there is a cyclic connection between calls to different modules. This can cause repetitive calls and also increase the complexity of understanding call traces for developers. This is a poor architectural practice for microservices.
 
Sebastian Copei et al. [2] demonstrate their IDE plugin SIARest to improve the development of microservice-based systems with static code analysis (Fig 1.).

<img width="1271" alt="img" src="https://github.com/TeodorsLisovenko/lisa-on-microservices/assets/45534919/1c9c8158-78c2-4a77-80f4-bcf0ebf99c14">

Fig. 1. Syntax checking with SIARest plugin in Visual Studio Code [2]. 

From their paper also is possible to derive code smells and issues. In the case of Copei’s paper their reference the GitHub repository where form code one can deduce that their tool is checking [2]:

```js
export const simpleTypeError = (resConf: string, resVal: Expression): SemanticError | undefined => {
  if (resConf === 'string' && resVal.kind !== SyntaxKind.StringLiteral) {
    return createSemanticError('Return value needs to be a string.', resVal.getStart(), resVal.end);
  } else if (resConf === 'number' && resVal.kind !== SyntaxKind.NumericLiteral) {
    return createSemanticError('Return value needs to be a number.', resVal.getStart(), resVal.end);
  } else if (resConf === 'boolean' && resVal.kind !== SyntaxKind.TrueKeyword && resVal.kind !== SyntaxKind.FalseKeyword) {
    return createSemanticError('Return value needs to be true or false.', resVal.getStart(), resVal.end);
  } else if (!['string', 'number', 'boolean'].includes(resConf)) {
    return createSemanticError(`Return value needs to be ${resConf}`, resVal.getStart(), resVal.end);
  }

  return undefined;
};
```

Function to raise error when there is field type differentiation between two microservice endpoints. 

Some more grouped by aim:

##### On issues, code smells: 

[1]	A. Walker, D. Das, and T. Cerny, “Automated Code-Smell Detection in Microservices Through Static Analysis: A Case StTowards Security-Aware Microservices: On Extracting Endpoint Data Access Operations to Determine Access Rightsudy,” Applied Sciences, vol. 10, no. 21, 2020, doi: 10.3390/app10217800.

[2]	M. and Z. A. Copei Sebastian and Schreiter, “Improving the Implementation of Microservice-Based Systems with Static Code Analysis,” in Agile Processes in Software Engineering and Extreme Programming – Workshops, P. Kruchten Philippe and Gregory, Ed., Cham: Springer Nature Switzerland, 2024, pp. 31–38.

[3]	R. Matar and J. Jahić, “An Approach for Evaluating the Potential Impact of Anti-Patterns on Microservices Performance,” in 2023 IEEE 20th International Conference on Software Architecture Companion (ICSA-C), 2023, pp. 167–170. doi: 10.1109/ICSA-C57050.2023.00044.

##### Discussion: 

[4]	T. Černý and D. Taibi, “Microservice-Aware Static Analysis: Opportunities, Gaps, and Advancements,” vol. 111, pp. 2:1-2:14, Jan. 2024, doi: 10.4230/OASIcs.Microservices.2020-2022.2.

#####  Optimization and validation:

[5]	P. Genfer and U. Zdun, “Avoiding Excessive Data Exposure Through Microservice APIs,” in Software Architecture, I. Gerostathopoulos, G. Lewis, T. Batista, and T. Bureš, Eds., Cham: Springer International Publishing, 2022, pp. 3–18.

##### Security:

[6]	A. Abdelfattah., M. Schiewe., J. Curtis., T. Cerny., and E. Song., “Towards Security-Aware Microservices: On Extracting Endpoint Data Access Operations to Determine Access Rights,” in Proceedings of the 13th International Conference on Cloud Computing and Services Science - CLOSER, SciTePress, 2023, pp. 15–23. doi: 10.5220/0011707500003488.

[7]	X. Li, Y. Chen, Z. Lin, X. Wang, and J. H. Chen, “Automatic Policy Generation for Inter-Service Access Control of Microservices,” in 30th USENIX Security Symposium (USENIX Security 21), USENIX Association, Aug. 2021, pp. 3971–3988. [Online]. Available: https://www.usenix.org/conference/usenixsecurity21/presentation/li-xing

##### On how to visualize microservice systems and discovery:

[8]	A. Fekete, B. Kovács, and Z. Porkoláb, “Automatic Dependency Tracking in Microservice-based Systems Using Static Analysis in Helm Charts,” in 2023 International Conference on Software, Telecommunications and Computer Networks (SoftCOM), 2023, pp. 1–7. doi: 10.23919/SoftCOM58365.2023.10271686.

[9]	T. Cerny, A. S. Abdelfattah, V. Bushong, A. Al Maruf, and D. Taibi, “Microservice Architecture Reconstruction and Visualization Techniques: A Review,” in 2022 IEEE International Conference on Service-Oriented System Engineering (SOSE), 2022, pp. 39–48. doi: 10.1109/SOSE55356.2022.00011.

[10]	M. Schiewe, J. Curtis, V. Bushong, and T. Cerny, “Advancing Static Code Analysis With Language-Agnostic Component Identification,” IEEE Access, vol. 10, pp. 30743–30761, 2022, doi: 10.1109/ACCESS.2022.3160485.

[11]	V. Bushong, D. Das, A. Al Maruf, and T. Cerny, “Using Static Analysis to Address Microservice Architecture Reconstruction,” in 2021 36th IEEE/ACM International Conference on Automated Software Engineering (ASE), 2021, pp. 1199–1201. doi: 10.1109/ASE51524.2021.9678749.

[12]	V. Bushong., D. Das., and T. Cerny., “Reconstructing the Holistic Architecture of Microservice Systems using Static Analysis,” in Proceedings of the 12th International Conference on Cloud Computing and Services Science - CLOSER, SciTePress, 2022, pp. 149–157. doi: 10.5220/0011032100003200.

## 3. On the localization of the code of interest

This section for its further examples will consider FastAPI and its specificities in a search and identification of code of interest. There could be multiple ways how microservices could work together, communicating, providing, and making requests. 

### Points of communication:

#### 1.	REST Endpoint: 

```
 Microservice A                     Microservice B
┌────────────────────┐            ┌──────────────────────────┐
│   /items/{item_id} │───────────►│        getItems()        │
├--------------------┤            │--------------------------│
│   /create_item     │            │--------------------------│
├--------------------┤            │--------------------------│
│   /delete_item     │            │--------------------------│
└────────────────────┘            └──────────────────────────┘
```
At the code side, this could look like this (minimal example):

**Microservice A**

```python
from fastapi import FastAPI, HTTPException

app = FastAPI()

fake_db = {} # In-memory database

@app.get("/items/{item_id}")
async def read_item(item_id: str):
    if item_id not in fake_db:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item_id": item_id, "data": fake_db[item_id]}


@app.post("/items/{item_id}")
async def create_item(item_id: str, data: str):
    if item_id in fake_db:
        raise HTTPException(status_code=400, detail="Item already exists")
    fake_db[item_id] = data
    return {"item_id": item_id, "data": data}


@app.delete("/items/{item_id}")
async def delete_item(item_id: str):
    if item_id not in fake_db:
        raise HTTPException(status_code=404, detail="Item not found")
    del fake_db[item_id]
    return {"message": "Item deleted successfully"}
```

**Microservice B**

```python
def getItems():
    response = requests.get("http://microservice_a:8000/items/1")

    if response.status_code == 200:
        return response.json()
    else:
        return None

items_data = getItems()
print(items_data)
```

#### 2.	Messaging broker: 

```
Microservice A              RabbitMQ                Microservice B
┌────────────────┐         ┌─────────────┐         ┌────────────────┐
│ send_message() │────────►│    Queue    │◄────────│receive_messages│
└────────────────┘         └─────────────┘         └────────────────┘
```

At the code side, this could look like this (minimal example):

**Microservice A**

```python
import pika

def send_message(message):
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    channel.queue_declare(queue='messages')
    channel.basic_publish(exchange='', routing_key='messages', body=message)
    print("Sent message:", message)
    connection.close()

message_to_send = "Hello from Microservice A!"
send_message(message_to_send)
```

**Microservice B**

```python
import pika

def receive_messages():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    channel.queue_declare(queue='messages')
    
    def callback(ch, method, properties, body):
        print("Received message:", body.decode())
    
    channel.basic_consume(queue='messages', on_message_callback=callback, auto_ack=True)
    print('Waiting for messages.')
    channel.start_consuming()

receive_messages()
```

Other communcation points to consider: `Shared database`, `GraphQL APIs`, `Service Mesh`, `Remote Procedure Calls (RPC)`, `WebSocket Communication`, `File Systems or Object Storage`, `Event Sourcing and Event Streams`. 

## 4. On dissection of syntax

### Steps of execution:

1.Take "REST endpoint" Microservice A and with the SARL dissect HTTP GET variation into parts for later analysis.   

```python
@app.get("/items/{itemId}")
async def read_item(item_id: boolean):
    if item_id not in fake_db:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item_id": item_id, "data": fake_db[item_id]}

```

2.With the Semantic Checks validate the following:

* Ensure that the endpoint string is given.
* Validate that the input argument is of a type numeric or string type and not any other (dict, boolean, set, list, etc).
* Ensure that the path variable in `/items/{item_id}` is the same as the argument of a function. 

Output these issues in a JSON file.

3.Introduce Microservice B that consumes Microservice’s A `/items/{item_id}` endpoint, and checks if:

* Endpoint paths match.
* Argument `itemId` is provided.

Output these issues in a JSON file.

4.Try to produce a visual graph where that captures previous Microservice A - Microservice B communication.

#### 1. Capturing the syntax with SARL

How code of interest is captured in some other academic papers:

1.M. Schiewe, J. Curtis, V. Bushong, and T. Cerny, “Advancing Static Code Analysis With Language-Agnostic Component Identification,” IEEE Access, vol. 10, pp. 30743–30761, 2022, doi: 10.1109/ACCESS.2022.3160485.

<img width="612" alt="spec-to-find" src="https://github.com/TeodorsLisovenko/lisa-on-microservices/assets/45534919/d38a7096-9953-4a9f-9ed4-4012b13988db">

2.I. Trabelsi et al., “From legacy to microservices: A type‐based approach for microservices identification using machine learning and semantic analysis,” Journal of Software: Evolution and Process, vol. 35, Mar. 2022, doi: 10.1002/smr.2503.

We propose MicroMiner, a microservice identiﬁcation approach that is based on static-relationship analyses between code elements as well as semantic analyses of the source code. Our approach relies on Machine Learning (ML) techniques and uses service types to guide the identiﬁcation of microservices from legacy monolithic systems.

We adopted a more reﬁned semantic analysis method that uses the pre-trained Word2Vec model based on Google News, which produces more accurate results on the semantic similarity between diﬀerent components of the monolithic project and ensures consistency in the context of microservices.

Starting with SARL:

```yaml
library fastapi:
    location fastapi
    method FastAPI: it.unive.pylisa.libraries.fastapi.FastAPI
        libtype fastapi.FastAPI*

    method get: it.unive.pylisa.libraries.fastapi.GetOperation
        libtype fastapi.Operation*
        param path type it.unive.lisa.program.type.StringType::INSTANCE
        param callback type it.unive.lisa.program.type.PyLambdaType::INSTANCE

    method HTTPException: it.unive.pylisa.libraries.fastapi.RaiseHttpException
        libtype fastapi.HTTPException*
        param status_code type it.unive.lisa.program.type.Int32Type::INSTANCE
        param detail type it.unive.lisa.program.type.StringType::INSTANCE

class fastapi.FastAPI:
    instance method add_route: it.unive.pylisa.libraries.fastapi.AddRoute
        type it.unive.lisa.type.VoidType::INSTANCE
        param self libtype fastapi.FastAPI*
        param path type it.unive.lisa.program.type.StringType::INSTANCE
        param callback type it.unive.lisa.program.type.PyLambdaType::INSTANCE

class fastapi.Operation:
    instance method execute: it.unive.pylisa.libraries.fastapi.ExecuteOperation
        type it.unive.lisa.type.VoidType::INSTANCE
        param self libtype fastapi.Operation*
        param request type it.unive.lisa.type.Untyped::INSTANCE

class fastapi.HTTPException:
    instance method respond: it.unive.pylisa.libraries.fastapi.RespondWithHttpException
        type it.unive.lisa.type.VoidType::INSTANCE
        param self libtype fastapi.HTTPException*
```

How would, for example, `GetOperation` look like in the Java capturing class:

<table>
<tr>
<td> Sarl </td> <td> Java capturing class </td>
</tr>
<tr>
<td> 

`GetOperation`

</td>
<td>

```java
public class GetOperation extends UnaryExpression implements PluggableStatement {
    private Statement st;

    public GetOperation(CFG cfg, CodeLocation location, Expression path) {
        super(cfg, location, "GetOperation", path);
    }

    @Override
    protected int compareSameClassAndParams(Statement o) {
        return 0;
    }

    @Override
    public void setOriginatingStatement(Statement st) {
        this.st = st;
    }

    public static GetOperation build(CFG cfg, CodeLocation location, Expression[] exprs) {
        if (exprs.length != 1) {
            throw new IllegalArgumentException("GetOperation requires exactly one argument: the path expression");
        }
        return new GetOperation(cfg, location, exprs[0]);
    }

    @Override
    public <A extends AbstractState<A>> AnalysisState<A> fwdUnarySemantics(
            InterproceduralAnalysis<A> interprocedural,
            AnalysisState<A> state,
            SymbolicExpression arg,
            StatementStore<A> expressions) throws SemanticException {
        return state;
    }
}
```
</td>
</tr>
</table>

### Currently perplexed here:
<img width="529" alt="image" src="https://github.com/TeodorsLisovenko/lisa-on-microservices/assets/45534919/bd37e1b0-4db5-4fea-8d08-3a9fe1e1af83">
