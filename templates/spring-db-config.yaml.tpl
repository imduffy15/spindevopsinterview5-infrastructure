spring:
  datasource:
    url: jdbc:mysql://{{ endpoint }}/{{ db_name }}?useSSL=false
    username: {{ db_name }}
    password: {{ db_password }}
