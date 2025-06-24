"""
AsyncAPI reference:
https://www.asyncapi.com/docs/reference/specification/v3.0.0

Some of the models are adapted from
[pydantic-asyncapi](https://github.com/asynq-io/pydantic-asyncapi).
Unfortunately, the original repository does not support python 3.8,
which this package does.
"""

from typing import Annotated, Any, Dict, List, Literal, Optional, TypeVar, Union
from pydantic import AnyUrl, BaseModel, Field, StringConstraints


ServerIdentifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_\-]+$")]

ComponentFieldName = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9\.\-_]+$")]

SchemaFormat = Literal[
    "application/vnd.aai.asyncapi;version=3.0.0",
    "application/vnd.aai.asyncapi+json;version=3.0.0",
    "application/vnd.aai.asyncapi+yaml;version=3.0.0",
    "application/schema+json;version=draft-07",
    "application/schema+yaml;version=draft-07",
    "application/vnd.apache.avro;version=1.9.0",
    "application/vnd.apache.avro+json;version=1.9.0",
    "application/vnd.apache.avro+yaml;version=1.9.0",
    "application/vnd.oai.openapi;version=3.0.0",
    "application/vnd.oai.openapi+json;version=3.0.0",
    "application/vnd.oai.openapi+yaml;version=3.0.0",
    "application/raml+yaml;version=1.0",
    "application/vnd.google.protobuf;version=2",
    "application/vnd.google.protobuf;version=3",
]


class Reference(BaseModel):
    """
    A simple object to allow referencing other components in the
    specification, internally and externally.

    The Reference Object is defined by [JSON
    Reference](https://tools.ietf.org/html/draft-pbryan-zyp-json-ref-03)
    and follows the same structure, behavior and rules. A JSON Reference
    SHALL only be used to refer to a schema that is formatted in either
    JSON or YAML. In the case of a YAML-formatted Schema, the JSON
    Reference SHALL be applied to the JSON representation of that
    schema. The JSON representation SHALL be made by applying the
    conversion described [here](#format).

    For this specification, reference resolution is done as defined by
    the JSON Reference specification and not by the JSON Schema
    specification.
    """

    ref: str = Field(alias="$ref")
    """
    **REQUIRED.** The reference string.
    """


T = TypeVar("T")
K = TypeVar("K", bound=str)

TypeOrRef = Optional[Union[T, Reference]]
TypeOrRefList = Optional[List[Union[T, Reference]]]
TypeOrRefMap = Optional[Dict[K, Union[T, Reference]]]
StrToTypeOrRefMap = TypeOrRefMap[str, T]
ComponentMap = TypeOrRefMap[ComponentFieldName, T]


class ExternalDocumentation(BaseModel):
    """
    Allows referencing an external resource for extended documentation.
    """

    description: Optional[str] = None
    """
    A short description of the target documentation. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    url: AnyUrl
    """
    **REQUIRED.** The URL for the target documentation. This MUST be in
    the form of an absolute URL.
    """


class CorrelationID(BaseModel):
    """
    An object that specifies an identifier at design time that can used
    for message tracing and correlation.

    For specifying and computing the location of a Correlation ID, a
    [runtime expression](#runtimeExpression) is used.
    """

    description: Optional[str] = None
    """
    An optional description of the identifier. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    location: str
    """
    **REQUIRED.** A [runtime expression](#runtimeExpression) that
    specifies the location of the correlation ID.
    """


class OAuthFlow(BaseModel):
    """
    Configuration details for a supported OAuth Flow
    """

    authorizationUrl: AnyUrl
    """
    **REQUIRED**. The authorization URL to be used for this flow. This
    MUST be in the form of an absolute URL.
    """

    tokenUrl: AnyUrl
    """
    **REQUIRED**. The token URL to be used for this flow. This MUST be
    in the form of an absolute URL.
    """

    refreshUrl: Optional[AnyUrl] = None
    """
    The URL to be used for obtaining refresh tokens. This MUST be in the
    form of an absolute URL.
    """

    availableScopes: Dict[str, str]
    """
    **REQUIRED**. The available scopes for the OAuth2 security scheme. A
    map between the scope name and a short description for it.
    """


class OAuthFlows(BaseModel):
    """
    Allows configuration of the supported OAuth Flows.
    """

    implicit: Optional[OAuthFlow] = None
    """
    Configuration for the OAuth Implicit flow.
    """

    password: Optional[OAuthFlow] = None
    """
    Configuration for the OAuth Resource Owner Protected Credentials flow.
    """

    clientCredentials: Optional[OAuthFlow] = None
    """
    Configuration for the OAuth Client Credentials flow.
    """

    authorizationCode: Optional[OAuthFlow] = None
    """
    Configuration for the OAuth Authorization Code flow.
    """


class SecurityScheme(BaseModel):
    """
    Defines a security scheme that can be used by the operations.
    Supported schemes are:

    - User/Password.
    - API key (either as user or as password).
    - X.509 certificate.
    - End-to-end encryption (either symmetric or asymmetric).
    - HTTP authentication.
    - HTTP API key.
    - OAuth2's common flows (Implicit, Resource Owner Protected
      Credentials, Client Credentials and Authorization Code) as defined
      in [RFC6749](https://tools.ietf.org/html/rfc6749).
    - [OpenID Connect
      Discovery](https://tools.ietf.org/html/draft-ietf-oauth-discovery-06).
    - SASL (Simple Authentication and Security Layer) as defined in
      [RFC4422](https://tools.ietf.org/html/rfc4422).
    """

    type: Literal[
        "userPassword",
        "apiKey",
        "X509",
        "symmetricEncryption",
        "asymmetricEncryption",
        "httpApiKey",
        "http",
        "oauth2",
        "openIdConnect",
        "plain",
        "scramSha256",
        "scramSha512",
        "gssapi",
    ]
    """
    **REQUIRED**. The type of the security scheme. Valid values are
    `"userPassword"`, `"apiKey"`, `"X509"`, `"symmetricEncryption"`,
    `"asymmetricEncryption"`, `"httpApiKey"`, `"http"`, `"oauth2"`,
    `"openIdConnect"`, `"plain"`, `"scramSha256"`, `"scramSha512"`, and
    `"gssapi"`.
    """

    description: Optional[str] = None
    """
    A short description for security scheme. [CommonMark
    syntax](https://spec.commonmark.org/) MAY be used for rich text
    representation.
    """

    name: str
    """
    **REQUIRED**. The name of the header, query or cookie parameter to be used.
    """

    in_: str = Field(alias="in")
    """
    **REQUIRED**. The location of the API key. Valid values are `"user"`
    and `"password"` for `apiKey` and `"query"`, `"header"` or
    `"cookie"` for `httpApiKey`.
    """

    scheme: str
    """
    **REQUIRED**. The name of the HTTP Authorization scheme to be used
    in the [Authorization header as defined in
    RFC7235](https://tools.ietf.org/html/rfc7235#section-5.1).
    """

    bearerFormat: Optional[str] = None
    """
    A hint to the client to identify how the bearer token is formatted.
    Bearer tokens are usually generated by an authorization server, so
    this information is primarily for documentation purposes.
    """

    flows: OAuthFlows
    """
    **REQUIRED**. An object containing configuration information for the
    flow types supported.
    """

    openIdConnectUrl: AnyUrl
    """
    **REQUIRED**. OpenId Connect URL to discover OAuth2 configuration
    values. This MUST be in the form of an absolute URL.
    """

    scopes: Optional[List[str]] = None
    """
    List of the needed scope names. An empty array means no scopes are
    needed.
    """


class JSONSchema(BaseModel):
    # TODO: Implement JSON Schema properties
    pass


class Schema(JSONSchema):
    """
    The Schema Object allows the definition of input and output data
    types. These types can be objects, but also primitives and arrays.
    This object is a superset of the [JSON Schema Specification Draft
    07](https://json-schema.org/). The empty schema (which allows any
    instance to validate) MAY be represented by the `boolean` value
    `true` and a schema which allows no instance to validate MAY be
    represented by the `boolean` value `false`.

    Further information about the properties can be found in [JSON
    Schema
    Core](https://tools.ietf.org/html/draft-handrews-json-schema-01) and
    [JSON Schema
    Validation](https://tools.ietf.org/html/draft-handrews-json-schema-validation-01).
    Unless stated otherwise, the property definitions follow the JSON
    Schema specification as referenced here. For other formats (e.g.,
    Avro, RAML, etc) see [Multi Format Schema
    Object](#multiFormatSchemaObject).
    """

    discriminator: Optional[str] = None
    """
    Adds support for polymorphism. The discriminator is the schema
    property name that is used to differentiate between other schema
    that inherit this schema. The property name used MUST be defined at
    this schema and it MUST be in the `required` property list. When
    used, the value MUST be the name of this schema or any schema that
    inherits it. See [Composition and Inheritance](#schemaComposition)
    for more details.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this schema.
    """

    deprecated: bool = False
    """
    Specifies that a schema is deprecated and SHOULD be transitioned out
    of usage. Default value is `false`.
    """


class MultiFormatSchema(BaseModel):
    """
    The Multi Format Schema Object represents a schema definition. It
    differs from the [Schema Object](#schemaObject) in that it supports
    multiple schema formats or languages (e.g., JSON Schema, Avro,
    etc.).
    """

    schemaFormat: SchemaFormat = "application/vnd.aai.asyncapi+json;version=3.0.0"
    """
    **Required**. A string containing the name of the schema format that
    is used to define the information. If `schemaFormat` is missing, it
    MUST default to
    `application/vnd.aai.asyncapi+json;version={{asyncapi}}` where
    `{{asyncapi}}` matches the [AsyncAPI Version
    String](#A2SVersionString). In such a case, this would make the
    Multi Format Schema Object equivalent to the [Schema
    Object](#schemaObject). When using [Reference
    Object](#referenceObject) within the schema, the `schemaFormat` of
    the resource being referenced MUST match the `schemaFormat` of the
    schema that contains the initial reference. For example, if you
    reference Avro `schema`, then `schemaFormat` of referencing resource
    and the resource being reference MUST match. <br/><br/>Check out the
    [supported schema formats table](#multiFormatSchemaFormatTable) for
    more information. Custom values are allowed but their implementation
    is OPTIONAL. A custom value MUST NOT refer to one of the schema
    formats listed in the
    [table](#multiFormatSchemaFormatTable).<br/><br/>When using
    [Reference Objects](#referenceObject) within the schema, the
    `schemaFormat` of the referenced resource MUST match the
    `schemaFormat` of the schema containing the reference.
    """

    schema_: Any = Field(alias="schema")
    """
    **Required**. Definition of the message payload. It can be of any
    type but defaults to [Schema Object](#schemaObject). It MUST match
    the schema format defined in
    [`schemaFormat`](#multiFormatSchemaObjectSchemaFormat), including
    the encoding type. E.g., Avro should be inlined as either a YAML or
    JSON object instead of as a string to be parsed as YAML or JSON.
    Non-JSON-based schemas (e.g., Protobuf or XSD) MUST be inlined as a
    string.
    """


class Tag(BaseModel):
    """
    Allows adding meta data to a single tag.
    """

    name: str
    """
    **REQUIRED.** The name of the tag.
    """

    description: Optional[str] = None
    """
    A short description for the tag. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this tag.
    """


class MessageExample(BaseModel):
    """
    Message Example Object represents an example of a [Message
    Object](#messageObject) and MUST contain either **headers** and/or
    **payload** fields.
    """

    headers: Optional[Dict[str, Any]] = None
    """
    The value of this field MUST validate against the [Message Object's
    headers](#messageObjectHeaders) field.
    """

    payload: Optional[Any] = None
    """
    The value of this field MUST validate against the [Message Object's
    payload](#messageObjectPayload) field.
    """

    name: Optional[str] = None
    """
    A machine-friendly name.
    """

    summary: Optional[str] = None
    """
    A short summary of what the example is about.
    """


class MessageBindings(BaseModel):
    """
    Map describing protocol-specific definitions for a message.
    """

    http: None = None
    ws: None = None
    kafka: None = None
    anypointmq: None = None
    amqp: None = None
    amqp1: None = None
    mqtt: None = None
    mqtt5: None = None
    nats: None = None
    jms: None = None
    sns: None = None
    solace: None = None
    sqs: None = None
    stomp: None = None
    redis: None = None
    mercure: None = None
    ibmmq: None = None
    googlepubsub: None = None
    pulsar: None = None


class MessageTrait(BaseModel):
    """
    Describes a trait that MAY be applied to a [Message
    Object](#messageObject). This object MAY contain any property from
    the [Message Object](#messageObject), except `payload` and `traits`.

    If you're looking to apply traits to an operation, see the
    [Operation Trait Object](#operationTraitObject).
    """

    headers: TypeOrRef[Union[MultiFormatSchema, Schema]] = None
    """
    Schema definition of the application headers. Schema MUST be a map
    of key-value pairs. It **MUST NOT** define the protocol headers. If
    this is a [Schema Object](#schemaObject), then the `schemaFormat`
    will be assumed to be
    "application/vnd.aai.asyncapi+json;version=`asyncapi`" where the
    version is equal to the [AsyncAPI Version
    String](#A2SVersionString).
    """

    correlationId: TypeOrRef[CorrelationID] = None
    """
    Definition of the correlation ID used for message tracing or
    matching.
    """

    contentType: Optional[str] = None
    """
    The content type to use when encoding/decoding a message's payload.
    The value MUST be a specific media type (e.g. `application/json`).
    When omitted, the value MUST be the one specified on the
    [defaultContentType](#defaultContentTypeString) field.
    """

    name: Optional[str] = None
    """
    A machine-friendly name for the message.
    """

    title: Optional[str] = None
    """
    A human-friendly title for the message.
    """

    summary: Optional[str] = None
    """
    A short summary of what the message is about.
    """

    description: Optional[str] = None
    """
    A verbose explanation of the message. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    tags: Optional[List[Tag]] = None
    """
    A list of tags for logical grouping and categorization of messages.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this message.
    """

    bindings: TypeOrRef[MessageBindings] = None
    """
    A map where the keys describe the name of the protocol and the
    values describe protocol-specific definitions for the message.
    """

    examples: Optional[List[MessageExample]] = None
    """
    List of examples.
    """


class Message(BaseModel):
    """
    Describes a message received on a given channel and operation.
    """

    headers: TypeOrRef[Union[MultiFormatSchema, Schema]] = None
    """
    Schema definition of the application headers. Schema MUST be a map
    of key-value pairs. It **MUST NOT** define the protocol headers. If
    this is a [Schema Object](#schemaObject), then the `schemaFormat`
    will be assumed to be
    "application/vnd.aai.asyncapi+json;version=`asyncapi`" where the
    version is equal to the [AsyncAPI Version
    String](#A2SVersionString).
    """

    payload: TypeOrRef[Union[MultiFormatSchema, Schema]] = None
    """
    Definition of the message payload. If this is a [Schema
    Object](#schemaObject), then the `schemaFormat` will be assumed to
    be "application/vnd.aai.asyncapi+json;version=`asyncapi`" where the
    version is equal to the [AsyncAPI Version
    String](#A2SVersionString).
    """

    correlationId: TypeOrRef[CorrelationID] = None
    """
    Definition of the correlation ID used for message tracing or matching.
    """

    contentType: Optional[str] = None
    """
    The content type to use when encoding/decoding a message's payload.
    The value MUST be a specific media type (e.g. `application/json`).
    When omitted, the value MUST be the one specified on the
    [defaultContentType](#defaultContentTypeString) field.
    """

    name: Optional[str] = None
    """
    A machine-friendly name for the message.
    """

    title: Optional[str] = None
    """
    A human-friendly title for the message.
    """

    summary: Optional[str] = None
    """
    A short summary of what the message is about.
    """

    description: Optional[str] = None
    """
    A verbose explanation of the message. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    tags: Optional[List[Tag]] = None
    """
    A list of tags for logical grouping and categorization of messages.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this message.
    """

    bindings: TypeOrRef[MessageBindings] = None
    """
    A map where the keys describe the name of the protocol and the
    values describe protocol-specific definitions for the message.
    """

    examples: Optional[List[MessageExample]] = None
    """
    List of examples.
    """

    traits: TypeOrRefList[MessageTrait] = None
    """
    A list of traits to apply to the message object. Traits MUST be
    merged using [traits merge mechanism](#traits-merge-mechanism). The
    resulting object MUST be a valid [Message Object](#messageObject).
    """


class OperationBindings(BaseModel):
    """
    Map describing protocol-specific definitions for an operation.
    """

    http: None = None
    ws: None = None
    kafka: None = None
    anypointmq: None = None
    amqp: None = None
    amqp1: None = None
    mqtt: None = None
    mqtt5: None = None
    nats: None = None
    jms: None = None
    sns: None = None
    solace: None = None
    sqs: None = None
    stomp: None = None
    redis: None = None
    mercure: None = None
    ibmmq: None = None
    googlepubsub: None = None
    pulsar: None = None


class ChannelBindings(BaseModel):
    """
    Map describing protocol-specific definitions for a channel.
    """

    http: None = None
    ws: None = None
    kafka: None = None
    anypointmq: None = None
    amqp: None = None
    amqp1: None = None
    mqtt: None = None
    mqtt5: None = None
    nats: None = None
    jms: None = None
    sns: None = None
    solace: None = None
    sqs: None = None
    stomp: None = None
    redis: None = None
    mercure: None = None
    ibmmq: None = None
    googlepubsub: None = None
    pulsar: None = None


class ServerBindings(BaseModel):
    """
    Map describing protocol-specific definitions for a server.
    """

    http: None = None
    ws: None = None
    kafka: None = None
    anypointmq: None = None
    amqp: None = None
    amqp1: None = None
    mqtt: None = None
    mqtt5: None = None
    nats: None = None
    jms: None = None
    sns: None = None
    solace: None = None
    sqs: None = None
    stomp: None = None
    redis: None = None
    mercure: None = None
    ibmmq: None = None
    googlepubsub: None = None
    pulsar: None = None


class Parameter(BaseModel):
    """
    Describes a parameter included in a channel address.
    """

    enum: Optional[List[str]] = None
    """
    An enumeration of string values to be used if the substitution
    options are from a limited set.
    """

    default: Optional[str] = None
    """
    The default value to use for substitution, and to send, if an
    alternate value is _not_ supplied.
    """

    description: Optional[str] = None
    """
    An optional description for the parameter. [CommonMark
    syntax](https://spec.commonmark.org/) MAY be used for rich text
    representation.
    """

    examples: Optional[List[str]] = None
    """
    An array of examples of the parameter value.
    """

    location: Optional[str] = None
    """
    A [runtime expression](#runtimeExpression) that specifies the
    location of the parameter value.
    """


class Contact(BaseModel):
    """
    Contact information for the exposed API.
    """

    name: Optional[str] = None
    """
    The identifying name of the contact person/organization.
    """

    url: Optional[AnyUrl] = None
    """
    The URL pointing to the contact information. MUST be in the form of
    an absolute URL.
    """

    email: Optional[str] = None
    """
    The email address of the contact person/organization. MUST be in the
    form of an email address.
    """


class License(BaseModel):
    """
    License information for the exposed API.
    """

    name: str
    """
    **REQUIRED.** The license name used for the API.
    """

    url: Optional[AnyUrl] = None
    """
    A URL to the license used for the API. MUST be in the form of an
    absolute URL.
    """


class Info(BaseModel):
    """
    The object provides metadata about the API. The metadata can be used
    by the clients if needed.
    """

    title: str
    """
    **REQUIRED.** The title of the application.
    """

    version: str
    """
    **REQUIRED** Provides the version of the application API (not to be
    confused with the specification version).
    """

    description: Optional[str] = None
    """
    A short description of the application. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    termsOfService: Optional[AnyUrl] = None
    """
    A URL to the Terms of Service for the API. This MUST be in the form
    of an absolute URL.
    """

    contact: Optional[Contact] = None
    """
    The contact information for the exposed API.
    """

    license: Optional[License] = None
    """
    The license information for the exposed API.
    """

    tags: Optional[List[Tag]] = None
    """
    A list of tags for application API documentation control. Tags can
    be used for logical grouping of applications.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation of the exposed API.
    """


class ServerVariable(BaseModel):
    """
    A server variable allows for a variable part of the server's URL.
    Variables are enclosed in curly braces and can be used to capture
    information such as usernames, passwords, hostnames, etc. The
    variables can be used in the `host` and `pathname` fields of the
    [Server Object](#serverObject).
    """

    enum: Optional[List[str]] = None
    """
    An enumeration of string values to be used if the substitution
    options are from a limited set.
    """

    default: Optional[str] = None
    """
    The default value to use for substitution, and to send, if an
    alternate value is _not_ supplied.
    """

    description: Optional[str] = None
    """
    An optional description for the server variable. [CommonMark
    syntax](https://spec.commonmark.org/) MAY be used for rich text
    representation.
    """

    examples: Optional[List[str]] = None
    """
    An array of examples of the server variable.
    """


class Server(BaseModel):
    """
    An object representing a message broker, a server or any other kind
    of computer program capable of sending and/or receiving data. This
    object is used to capture details such as URIs, protocols and
    security configuration. Variable substitution can be used so that
    some details, for example usernames and passwords, can be injected
    by code generation tools.
    """

    host: str
    """
    **REQUIRED**. The server host name. It MAY include the port. This
    field supports Server Variables. Variable substitution will be made
    when a variable is named in `{`braces`}`.
    """

    protocol: str
    """
    **REQUIRED**. The protocol this server supports for connection.
    """

    protocolVersion: Optional[str] = None
    """
    The version of the protocol used for connection. For instance: AMQP
    `0.9.1`, HTTP `2.0`, Kafka `1.0.0`, etc.
    """

    pathname: Optional[str] = None
    """
    The path to a resource in the host. This field supports Server
    Variables. Variable substitutions will be
    made when a variable is named in `{`braces`}`.
    """

    description: Optional[str] = None
    """
    An optional string describing the server. [CommonMark
    syntax](https://spec.commonmark.org/) MAY be used for rich text
    representation.
    """

    title: Optional[str] = None
    """
    A human-friendly title for the server.
    """

    summary: Optional[str] = None
    """
    A short summary of the server.
    """

    variables: StrToTypeOrRefMap[ServerVariable] = None
    """
    A map between a variable name and its value.  The value is used for
    substitution in the server's `host` and `pathname` template.
    """

    security: TypeOrRefList[SecurityScheme] = None
    """
    A declaration of which security schemes can be used with this
    server. The list of values includes alternative [security scheme
    objects](#securitySchemeObject) that can be used. Only one of the
    security scheme objects need to be satisfied to authorize a
    connection or operation.
    """

    tags: Optional[List[Tag]] = None
    """
    A list of tags for logical grouping and categorization of servers.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this server.
    """

    bindings: TypeOrRef[ServerBindings] = None
    """
    A map where the keys describe the name of the protocol and the values
    describe protocol-specific definitions for the server.
    """


class Channel(BaseModel):
    """
    Describes a shared communication channel.
    """

    address: Optional[str] = None
    """
    An optional string representation of this channel's address. The
    address is typically the "topic name", "routing key", "event type",
    or "path". When `null` or absent, it MUST be interpreted as unknown.
    This is useful when the address is generated dynamically at runtime
    or can't be known upfront. It MAY contain Channel Address
    Expressions. Query parameters and fragments SHALL NOT be used,
    instead use bindings to define them.
    """

    messages: StrToTypeOrRefMap[Message] = None
    """
    A map of the messages that will be sent to this channel by any
    application at any time. **Every message sent to this channel MUST be
    valid against one, and only one, of the message objects defined in
    this map.**
    """

    title: Optional[str] = None
    """
    A human-friendly title for the channel.
    """

    summary: Optional[str] = None
    """
    A short summary of the channel.
    """

    description: Optional[str] = None
    """
    An optional description of this channel. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    servers: Optional[List[Reference]] = None
    """
    An array of `$ref` pointers to the definition of the servers in
    which this channel is available. If the channel is located in the
    root Channels Object, it MUST point to a subset of server
    definitions located in the root Servers Object, and MUST NOT point
    to a subset of server definitions located in the Components Object
    or anywhere else. If the channel is located in the Components
    Object, it MAY point to a Server Objects in any location. If
    `servers` is absent or empty, this channel MUST be available on all
    the servers defined in the Servers Object. Please note the `servers`
    property value MUST be an array of Reference Objects and, therefore,
    MUST NOT contain an array of Server Objects. However, it is
    RECOMMENDED that parsers (or other software) dereference this
    property for a better development experience.
    """

    parameters: Optional[Dict[str, Parameter]] = None
    """
    A map of the parameters included in the channel address. It MUST be present
    only when the address contains Channel Address Expressions.
    """

    tags: Optional[List[Tag]] = None
    """
    A list of tags for logical grouping of channels.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this channel.
    """

    bindings: TypeOrRef[ChannelBindings] = None
    """
    A map where the keys describe the name of the protocol and the values
    describe protocol-specific definitions for the channel.
    """


class OperationTrait(BaseModel):
    """
    Describes a trait that MAY be applied to an [Operation
    Object](#operationObject). This object MAY contain any property from
    the [Operation Object](#operationObject), except the `action`,
    `channel`, `messages` and `traits` ones.

    If you're looking to apply traits to a message, see the [Message Trait
    Object](#messageTraitObject).
    """

    title: Optional[str] = None
    """
    A human-friendly title for the operation.
    """

    summary: Optional[str] = None
    """
    A short summary of what the operation is about.
    """

    description: Optional[str] = None
    """
    A verbose explanation of the operation. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    security: TypeOrRefList[SecurityScheme] = None
    """
    A declaration of which security schemes are associated with this
    operation. Only one of the [security scheme
    objects](#securitySchemeObject) MUST be satisfied to authorize an
    operation. In cases where [Server Security](#serverObjectSecurity)
    also applies, it MUST also be satisfied.
    """

    tags: Optional[List[Tag]] = None
    """
    A list of tags for logical grouping and categorization of operations.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this operation.
    """

    bindings: TypeOrRef[OperationBindings] = None
    """
    A map where the keys describe the name of the protocol and the
    values describe protocol-specific definitions for the operation.
    """


class OperationReplyAddress(BaseModel):
    """
    An object that specifies where an operation has to send the reply.

    For specifying and computing the location of a reply address, a
    [runtime expression](#runtimeExpression) is used.
    """

    description: Optional[str] = None
    """
    An optional description of the address. [CommonMark
    syntax](https://spec.commonmark.org/) can be used for rich text
    representation.
    """

    location: Optional[str] = None
    """
    **REQUIRED.** A [runtime expression](#runtimeExpression) that
    specifies the location of the reply address.
    """


class OperationReply(BaseModel):
    """
    Describes the reply part that MAY be applied to an Operation Object.
    If an operation implements the request/reply pattern, the reply
    object represents the response message.
    """

    address: TypeOrRef[OperationReplyAddress] = None
    """
    Definition of the address that implementations MUST use for the reply.
    """

    channel: Optional[Reference] = None
    """
    A `$ref` pointer to the definition of the channel in which this
    operation is performed. When [address](#operationReplyAddressObject)
    is specified, the [`address` property](#channelObjectAddress) of the
    channel referenced by this property MUST be either `null` or not
    defined. If the operation reply is located inside a [root Operation
    Object](#operationObject), it MUST point to a channel definition
    located in the [root Channels Object](#channelsObject), and MUST NOT
    point to a channel definition located in the [Components
    Object](#componentsObject) or anywhere else. If the operation reply
    is located inside an [Operation Object] in the [Components
    Object](#componentsObject) or in the [Replies
    Object](#componentsReplies) in the [Components
    Object](#componentsObject), it MAY point to a [Channel
    Object](#channelObject) in any location. Please note the `channel`
    property value MUST be a [Reference Object](#referenceObject) and,
    therefore, MUST NOT contain a [Channel Object](#channelObject).
    However, it is RECOMMENDED that parsers (or other software)
    dereference this property for a better development experience.
    """

    messages: Optional[List[Reference]] = None
    """
    A list of `$ref` pointers pointing to the supported [Message
    Objects](#messageObject) that can be processed by this operation as
    reply. It MUST contain a subset of the messages defined in the
    [channel referenced in this operation
    reply](#operationObjectChannel), and MUST NOT point to a subset of
    message definitions located in the [Components
    Object](#componentsObject) or anywhere else. **Every message
    processed by this operation MUST be valid against one, and only one,
    of the [message objects](#messageObject) referenced in this list.**
    Please note the `messages` property value MUST be a list of
    [Reference Objects](#referenceObject) and, therefore, MUST NOT
    contain [Message Objects](#messageObject). However, it is
    RECOMMENDED that parsers (or other software) dereference this
    property for a better development experience.
    """


class Operation(BaseModel):
    """
    Describes a specific operation.
    """

    action: Literal["send", "receive"]
    """
    **Required**. Use `send` when it's expected that the application will send
    a message to the given `channel`, and `receive` when the application should
    expect receiving messages from the given `channel`.
    """

    channel: Reference
    """
    **Required**. A `$ref` pointer to the definition of the channel in which
    this operation is performed. If the operation is located in the root
    Operations Object, it MUST point to a channel definition located in the
    root Channels Object, and MUST NOT point to a channel definition located in
    the Components Object or anywhere else. If the operation is located in the
    Components Object, it MAY point to a Channel Object in any location. Please
    note the `channel` property value MUST be a Reference Object and,
    therefore, MUST NOT contain a Channel Object. However, it is RECOMMENDED
    that parsers (or other software) dereference this property for a better
    development experience.
    """

    title: Optional[str] = None
    """
    A human-friendly title for the operation.
    """

    summary: Optional[str] = None
    """
    A short summary of what the operation is about.
    """

    description: Optional[str] = None
    """
    A verbose explanation of the operation. [CommonMark
    syntax](http://spec.commonmark.org/) can be used for rich text
    representation.
    """

    security: TypeOrRefList[SecurityScheme] = None
    """
    A declaration of which security schemes are associated with this operation.
    Only one of the [security scheme objects](#securitySchemeObject) MUST be
    satisfied to authorize an operation. In cases where [Server
    Security](#serverObjectSecurity) also applies, it MUST also be satisfied.
    """

    tags: Optional[List[Tag]] = None
    """
    A list of tags for logical grouping and categorization of operations.
    """

    externalDocs: TypeOrRef[ExternalDocumentation] = None
    """
    Additional external documentation for this operation.
    """

    bindings: TypeOrRef[OperationBindings] = None
    """
    A map where the keys describe the name of the protocol and the
    values describe protocol-specific definitions for the operation.
    """

    traits: TypeOrRefList[OperationTrait] = None
    """
    A list of traits to apply to the operation object. Traits MUST be
    merged using [traits merge mechanism](#traits-merge-mechanism). The
    resulting object MUST be a valid [Operation
    Object](#operationObject). 
    """

    messages: Optional[List[Reference]] = None
    """
    A list of `$ref` pointers pointing to the supported [Message
    Objects](#messageObject) that can be processed by this operation. It
    MUST contain a subset of the messages defined in the [channel
    referenced in this operation](#operationObjectChannel), and MUST NOT
    point to a subset of message definitions located in the [Messages
    Object](#componentsMessages) in the [Components
    Object](#componentsObject) or anywhere else. **Every message
    processed by this operation MUST be valid against one, and only one,
    of the [message objects](#messageObject) referenced in this list.**
    Please note the `messages` property value MUST be a list of
    [Reference Objects](#referenceObject) and, therefore, MUST NOT
    contain [Message Objects](#messageObject). However, it is
    RECOMMENDED that parsers (or other software) dereference this
    property for a better development experience. <p>**Note**: excluding
    this property from the Operation implies that all messages from the
    channel will be included. Explicitly set the `messages` property to
    `[]` if this operation should contain no messages.</p>
    """

    reply: TypeOrRef[OperationReply] = None
    """
    The definition of the reply in a request-reply operation.
    """


class Components(BaseModel):
    """
    Holds a set of reusable objects for different aspects of the
    AsyncAPI specification.
    All objects defined within the components object will have no effect
    on the API unless they are explicitly referenced from properties
    outside the components object.
    """

    schemas: ComponentMap[Union[MultiFormatSchema, Schema]] = None
    """
    An object to hold reusable [Schema Object](#schemaObject). If this
    is a [Schema Object](#schemaObject), then the `schemaFormat` will be
    assumed to be "application/vnd.aai.asyncapi+json;version=`asyncapi`"
    where the version is equal to the [AsyncAPI Version
    String](#A2SVersionString). 
    """

    servers: ComponentMap[Server] = None
    """
    An object to hold reusable [Server Objects](#serverObject).
    """

    channels: ComponentMap[Channel] = None
    """
    An object to hold reusable [Channel Objects](#channelObject).
    """

    operations: ComponentMap[Operation] = None
    """
    An object to hold reusable [Operation Objects](#operationObject).
    """

    messages: ComponentMap[Message] = None
    """
    An object to hold reusable [Message Objects](#messageObject).
    """

    securitySchemes: ComponentMap[SecurityScheme] = None
    """
    An object to hold reusable [Security Scheme
    Objects](#securitySchemeObject).
    """

    serverVariables: ComponentMap[ServerVariable] = None
    """
    An object to hold reusable [Server Variable Objects](#serverVariableObject).
    """

    parameters: ComponentMap[Parameter] = None
    """
    An object to hold reusable [Parameter Objects](#parameterObject).
    """

    correlationIds: ComponentMap[CorrelationID] = None
    """
    An object to hold reusable [Correlation ID
    Objects](#correlationIdObject).
    """

    replies: ComponentMap[OperationReply] = None
    """
    An object to hold reusable [Operation Reply Objects](#operationReplyObject).
    """

    replyAddresses: ComponentMap[OperationReplyAddress] = None
    """
    An object to hold reusable [Operation Reply Address
    Objects](#operationReplyAddressObject).
    """

    externalDocs: ComponentMap[ExternalDocumentation] = None
    """
    An object to hold reusable [External Documentation
    Objects](#externalDocumentationObject).
    """

    tags: ComponentMap[Tag] = None
    """
    An object to hold reusable [Tag Objects](#tagObject).
    """

    operationTraits: ComponentMap[OperationTrait] = None
    """
    An object to hold reusable [Operation Trait Objects](#operationTraitObject).
    """

    messageTraits: ComponentMap[MessageTrait] = None
    """
    An object to hold reusable [Message Trait Objects](#messageTraitObject).
    """

    serverBindings: ComponentMap[ServerBindings] = None
    """
    An object to hold reusable [Server Bindings Objects](#serverBindingsObject).
    """

    channelBindings: ComponentMap[ChannelBindings] = None
    """
    An object to hold reusable [Channel Bindings Objects](#channelBindingsObject).
    """

    operationBindings: ComponentMap[OperationBindings] = None
    """
    An object to hold reusable [Operation Bindings Objects](#operationBindingsObject).
    """

    messageBindings: ComponentMap[MessageBindings] = None
    """
    An object to hold reusable [Message Bindings
    Objects](#messageBindingsObject).
    """


class AsyncAPI(BaseModel):
    """
    This is the root document object for the API specification. It
    combines resource listing and API declaration together into one
    document.
    """

    asyncapi: str
    """
    **REQUIRED.** Specifies the AsyncAPI Specification version being
    used. It can be used by tooling Specifications and clients to
    interpret the version. The structure shall be
    `major`.`minor`.`patch`, where `patch` versions _must_ be compatible
    with the existing `major`.`minor` tooling. Typically patch versions
    will be introduced to address errors in the documentation, and
    tooling should typically be compatible with the corresponding
    `major`.`minor` (1.0.*). Patch versions will correspond to patches
    of this document.
    """

    id: Optional[str] = None
    """
    Identifier of the application the AsyncAPI document is defining.
    """

    info: Info
    """
    **REQUIRED.** Provides metadata about the application API. The
    metadata can be used by the clients if needed.
    """

    servers: TypeOrRefMap[ServerIdentifier, Server] = None
    """
    Provides connection details of servers.
    """

    defaultContentType: Optional[str] = None
    """
    Default content type to use when encoding/decoding a message's
    payload.
    """

    channels: StrToTypeOrRefMap[Channel] = None
    """
    The channels used by this application.
    """

    operations: StrToTypeOrRefMap[Operation] = None
    """
    The operations this application MUST implement.
    """

    components: Optional[Components] = None
    """
    An element to hold various reusable objects for the specification.
    Everything that is defined inside this object represents a resource
    that MAY or MAY NOT be used in the rest of the document and MAY or
    MAY NOT be used by the implemented Application.
    """
