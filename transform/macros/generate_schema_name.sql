{# Force all models into the schema configured on each model (marts here),
   never the dbt default of '<target_schema>_<custom_schema>'. Without this
   override the +grants on grafana_ro would land on the wrong schema and
   spec §10.4 would fail. #}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {%- if custom_schema_name is none -%}
        {{ target.schema | trim }}
    {%- else -%}
        {{ custom_schema_name | trim }}
    {%- endif -%}
{%- endmacro %}
