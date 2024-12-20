%% Generated by the Erlang ASN.1 compiler. Version: 5.3.1
%% Purpose: Erlang record definitions for each named and unnamed
%% SEQUENCE and SET, and macro definitions for each value
%% definition in module InformationFramework.

-ifndef(_INFORMATIONFRAMEWORK_HRL_).
-define(_INFORMATIONFRAMEWORK_HRL_, true).

-record('Attribute', {
  type,
  values,
  valuesWithContext = asn1_NOVALUE
}).

-record('Attribute_valuesWithContext_SETOF', {
  value,
  contextList
}).

-record('Context', {
  contextType,
  contextValues,
  fallback = asn1_DEFAULT
}).

-record('AttributeValueAssertion', {
  type,
  assertion,
  assertedContexts = asn1_NOVALUE
}).

-record('ContextAssertion', {
  contextType,
  contextValues
}).

-record('AttributeTypeAssertion', {
  type,
  assertedContexts = asn1_NOVALUE
}).

-record('AttributeTypeAndValue', {
  type,
  value
}).

-record('AttributeTypeAndDistinguishedValue', {
  type,
  value,
  primaryDistinguished = asn1_DEFAULT,
  valuesWithContext = asn1_NOVALUE
}).

-record('AttributeTypeAndDistinguishedValue_valuesWithContext_SETOF', {
  distingAttrValue = asn1_NOVALUE,
  contextList
}).

-record('SubtreeSpecification', {
  base = asn1_DEFAULT,
  specificExclusions = asn1_NOVALUE,
  minimum = asn1_DEFAULT,
  maximum = asn1_NOVALUE,
  specificationFilter = asn1_NOVALUE
}).

-record('ChopSpecification', {
  specificExclusions = asn1_NOVALUE,
  minimum = asn1_DEFAULT,
  maximum = asn1_NOVALUE
}).

-record('DITStructureRule', {
  ruleIdentifier,
  nameForm,
  superiorStructureRules = asn1_NOVALUE
}).

-record('DITContentRule', {
  structuralObjectClass,
  auxiliaries = asn1_NOVALUE,
  mandatory = asn1_NOVALUE,
  optional = asn1_NOVALUE,
  precluded = asn1_NOVALUE
}).

-record('DITContextUse', {
  attributeType,
  mandatoryContexts = asn1_NOVALUE,
  optionalContexts = asn1_NOVALUE
}).

-record('SearchRuleDescription', {
  id,
  dmdId,
  serviceType = asn1_NOVALUE,
  userClass = asn1_NOVALUE,
  inputAttributeTypes = asn1_NOVALUE,
  attributeCombination = asn1_DEFAULT,
  outputAttributeTypes = asn1_NOVALUE,
  defaultControls = asn1_NOVALUE,
  mandatoryControls = asn1_NOVALUE,
  searchRuleControls = asn1_NOVALUE,
  familyGrouping = asn1_NOVALUE,
  familyReturn = asn1_NOVALUE,
  relaxation = asn1_NOVALUE,
  additionalControl = asn1_NOVALUE,
  allowedSubset = asn1_DEFAULT,
  imposedSubset = asn1_NOVALUE,
  entryLimit = asn1_NOVALUE,
  name = asn1_NOVALUE,
  description = asn1_NOVALUE,
  obsolete = asn1_DEFAULT
}).

-record('SearchRule', {
  id,
  dmdId,
  serviceType = asn1_NOVALUE,
  userClass = asn1_NOVALUE,
  inputAttributeTypes = asn1_NOVALUE,
  attributeCombination = asn1_DEFAULT,
  outputAttributeTypes = asn1_NOVALUE,
  defaultControls = asn1_NOVALUE,
  mandatoryControls = asn1_NOVALUE,
  searchRuleControls = asn1_NOVALUE,
  familyGrouping = asn1_NOVALUE,
  familyReturn = asn1_NOVALUE,
  relaxation = asn1_NOVALUE,
  additionalControl = asn1_NOVALUE,
  allowedSubset = asn1_DEFAULT,
  imposedSubset = asn1_NOVALUE,
  entryLimit = asn1_NOVALUE
}).

-record('SearchRuleId', {
  id,
  dmdId
}).

-record('RequestAttribute', {
  attributeType,
  includeSubtypes = asn1_DEFAULT,
  selectedValues = asn1_NOVALUE,
  defaultValues = asn1_NOVALUE,
  contexts = asn1_NOVALUE,
  contextCombination = asn1_DEFAULT,
  matchingUse = asn1_NOVALUE
}).

-record('RequestAttribute_defaultValues_SEQOF', {
  entryType = asn1_NOVALUE,
  values
}).

-record('ContextProfile', {
  contextType,
  contextValue = asn1_NOVALUE
}).

-record('MatchingUse', {
  restrictionType,
  restrictionValue
}).

-record('ResultAttribute', {
  attributeType,
  outputValues = asn1_NOVALUE,
  contexts = asn1_NOVALUE
}).

-record('ControlOptions', {
  serviceControls = asn1_DEFAULT,
  searchOptions = asn1_DEFAULT,
  hierarchyOptions = asn1_NOVALUE
}).

-record('EntryLimit', {
  default,
  max
}).

-record('RelaxationPolicy', {
  basic = asn1_DEFAULT,
  tightenings = asn1_NOVALUE,
  relaxations = asn1_NOVALUE,
  maximum = asn1_NOVALUE,
  minimum = asn1_DEFAULT
}).

-record('MRMapping', {
  mapping = asn1_NOVALUE,
  substitution = asn1_NOVALUE
}).

-record('Mapping', {
  mappingFunction,
  level = asn1_DEFAULT
}).

-record('MRSubstitution', {
  attribute,
  oldMatchingRule = asn1_NOVALUE,
  newMatchingRule = asn1_NOVALUE
}).

-define('id-oc-top', {2,5,6,0}).
-define('id-oc-alias', {2,5,6,1}).
-define('id-oc-parent', {2,5,6,28}).
-define('id-oc-child', {2,5,6,29}).
-define('id-at-objectClass', {2,5,4,0}).
-define('id-at-aliasedEntryName', {2,5,4,1}).
-define('id-mr-objectIdentifierMatch', {2,5,13,0}).
-define('id-mr-distinguishedNameMatch', {2,5,13,1}).
-define('id-oa-excludeAllCollectiveAttributes', {2,5,18,0}).
-define('id-oa-createTimestamp', {2,5,18,1}).
-define('id-oa-modifyTimestamp', {2,5,18,2}).
-define('id-oa-creatorsName', {2,5,18,3}).
-define('id-oa-modifiersName', {2,5,18,4}).
-define('id-oa-administrativeRole', {2,5,18,5}).
-define('id-oa-subtreeSpecification', {2,5,18,6}).
-define('id-oa-collectiveExclusions', {2,5,18,7}).
-define('id-oa-subschemaTimestamp', {2,5,18,8}).
-define('id-oa-hasSubordinates', {2,5,18,9}).
-define('id-oa-subschemaSubentryList', {2,5,18,10}).
-define('id-oa-accessControlSubentryList', {2,5,18,11}).
-define('id-oa-collectiveAttributeSubentryList', {2,5,18,12}).
-define('id-oa-contextDefaultSubentryList', {2,5,18,13}).
-define('id-oa-contextAssertionDefault', {2,5,18,14}).
-define('id-oa-serviceAdminSubentryList', {2,5,18,15}).
-define('id-oa-searchRules', {2,5,18,16}).
-define('id-oa-hierarchyLevel', {2,5,18,17}).
-define('id-oa-hierarchyBelow', {2,5,18,18}).
-define('id-oa-hierarchyParent', {2,5,18,19}).
-define('id-sc-subentry', {2,5,17,0}).
-define('id-sc-accessControlSubentry', {2,5,17,1}).
-define('id-sc-collectiveAttributeSubentry', {2,5,17,2}).
-define('id-sc-contextAssertionSubentry', {2,5,17,3}).
-define('id-sc-serviceAdminSubentry', {2,5,17,4}).
-define('id-nf-subentryNameForm', {2,5,15,16}).
-define('id-ar-autonomousArea', {2,5,23,1}).
-define('id-ar-accessControlSpecificArea', {2,5,23,2}).
-define('id-ar-accessControlInnerArea', {2,5,23,3}).
-define('id-ar-subschemaAdminSpecificArea', {2,5,23,4}).
-define('id-ar-collectiveAttributeSpecificArea', {2,5,23,5}).
-define('id-ar-collectiveAttributeInnerArea', {2,5,23,6}).
-define('id-ar-contextDefaultSpecificArea', {2,5,23,7}).
-define('id-ar-serviceSpecificArea', {2,5,23,8}).
-define('id-at', {2,5,4}).
-define('id-at-countryName', {2,5,4,6}).
-define('id-at-organizationName', {2,5,4,10}).
-define('id-at-serialNumber', {2,5,4,5}).
-define('id-at-stateOrProvinceName', {2,5,4,8}).
-define('id-at-localityName', {2,5,4,7}).
-define('id-at-commonName', {2,5,4,3}).
-define('id-at-organizationalUnitName', {2,5,4,11}).
-endif. %% _INFORMATIONFRAMEWORK_HRL_
