defmodule Amps.UserIdentities do
  use PowAssent.Ecto.UserIdentities.Context,
    users_context: Amps.Users,
    user: Amps.Users.User

  def all(user) do
    pow_assent_all(user)
  end
end

defmodule Amps.Users do
  import Pow.Context
  alias Pow.{Config, Store.CredentialsCache}
  alias PowPersistentSession.Store.PersistentSessionCache
  require Logger

  defp authmethod() do
    Application.get_env(:amps_web, AmpsWeb.Endpoint)[:authmethod]
  end

  def index(config) do
    if config do
      case Keyword.get(config, :env) do
        "" ->
          "users"

        other ->
          other <> "-users"
      end
    else
      "users"
    end
  end

  def authenticate(body, config) do
    IO.inspect("authenticate")

    case body["provider"] do
      "google" ->
        google_upsert(body)

      _ ->
        case authmethod() do
          "vault" ->
            Amps.Users.Vault.authenticate(body)

          _ ->
            Amps.Users.DB.authenticate(body, config)
        end
    end

    # Use params to look up user and verify password with `MyApp.Users.User.verify_password/2`
  end

  def create(body, config \\ nil) do
    case authmethod() do
      "vault" ->
        Amps.Users.Vault.create(body)

      _ ->
        Amps.Users.DB.create(body, config)
    end
  end

  def update(_user, _params) do
    IO.puts("update")
    {:error, :not_implemented}
  end

  def delete(body, config \\ nil) do
    case authmethod() do
      "vault" ->
        Amps.Users.Vault.create(body)

      _ ->
        Amps.Users.DB.create(body, config)
    end
  end

  def get_by(clauses, config \\ nil) do
    filter =
      Enum.reduce(clauses, %{}, fn {key, value}, acc ->
        if key == :id do
          Map.put(acc, :_id, value)
        else
          Map.put(acc, key, value)
        end
      end)

    case Amps.DB.find_one(index(config), filter) do
      nil ->
        nil

      obj ->
        convert_to_user_struct(obj)
    end
  end

  def convert_to_user_struct(user) do
    user =
      Map.put(user, "id", user["_id"])
      |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)

    struct(Amps.Users.User, user)
  end

  def google_upsert(params) do
    userinfo = params["userinfo"]
    uid = params["uid"]
    user = Amps.DB.find_one("users", %{google_id: uid})

    if user do
      convert_to_user_struct(user)
    else
      user =
        %{}
        |> Map.put("firstname", userinfo["given_name"])
        |> Map.put("lastname", userinfo["family_name"])
        |> Map.put("email", userinfo["email"])
        |> Map.put("username", userinfo["email"])
        |> Map.put("google_id", uid)
        |> Map.put("provider", "google")
        |> Map.merge(%{"approved" => false, "role" => "Guest"})

      id = Amps.DB.insert("users", user)

      user = Map.put(user, :id, id)
      struct(Amps.Users.User, user)
    end
  end

  def custom_auth(params, env \\ "") do
    config = config(env)

    # The store caches will use their default `:ttl` settting. To change the
    # `:ttl`, `Keyword.put(store_config, :ttl, :timer.minutes(10))` can be
    # passed in as the first argument instead of `store_config`.

    authenticate(params, config)
    |> case do
      nil ->
        {:error, "Unable to Authenticate"}

      user ->
        create(user, config)
    end
  end

  def create_session(user, env \\ "") do
    config = config(env)

    store_config = store_config(config)
    access_token = Pow.UUID.generate()
    renewal_token = Pow.UUID.generate()

    conn =
      %Plug.Conn{
        secret_key_base: Application.get_env(:amps, :secret_key_base)
      }
      |> Plug.Conn.put_private(:pow_config, config)

    access = Pow.Plug.sign_token(conn, "user_auth", access_token, config)
    renew = Pow.Plug.sign_token(conn, "user_auth", renewal_token, config)

    CredentialsCache.put(
      store_config,
      access_token,
      {user, [renewal_token: renewal_token]}
    )

    PersistentSessionCache.put(
      store_config,
      renewal_token,
      {user, [access_token: access_token]}
    )

    %{
      "success" => true,
      "access_token" => access,
      "renewal_token" => renew,
      "user" => convert_to_binary_map(user)
    }
  end

  defp store_config(config) do
    backend = Config.get(config, :cache_store_backend, Pow.Store.Backend.EtsCache)

    [backend: backend]
  end

  def renew_session(renewal_token, env \\ "") do
    config = config(env)

    store_config = store_config(config)

    conn =
      %Plug.Conn{
        secret_key_base: Application.get_env(:amps, :secret_key_base)
      }
      |> Plug.Conn.put_private(:pow_config, config)

    with {:ok, token} <- Pow.Plug.verify_token(conn, "user_auth", renewal_token, config),
         {user, metadata} <-
           Pow.Store.Base.get(
             store_config,
             PersistentSessionCache.backend_config(store_config),
             token
           ),
         user <- Amps.Users.get_by(%{"_id" => user.id}, config) do
      CredentialsCache.delete(store_config, metadata[:access_token])
      PersistentSessionCache.delete(store_config, token)

      create_session(user, config)
    else
      _ ->
        %{"success" => false, "error" => "Invalid Token"}
    end
  end

  def verify_session(access_token, env \\ "") do
    config = config(env)

    conn =
      %Plug.Conn{
        secret_key_base: Application.get_env(:amps, :secret_key_base)
      }
      |> Plug.Conn.put_private(:pow_config, config)

    with {:ok, token} <- Pow.Plug.verify_token(conn, "user_auth", access_token, config),
         {user, _metadata} <- CredentialsCache.get(store_config(config), token) do
      %{"success" => true}
    else
      _any -> %{"success" => false}
    end
  end

  def delete_session(access_token, env \\ "") do
    config = config(env)
    store_config = store_config(config)

    conn =
      %Plug.Conn{
        secret_key_base: Application.get_env(:amps, :secret_key_base)
      }
      |> Plug.Conn.put_private(:pow_config, config)

    with {:ok, token} = Pow.Plug.verify_token(conn, "user_auth", access_token, config),
         {_user, metadata} <- CredentialsCache.get(store_config, token) do
      PersistentSessionCache.delete(store_config, metadata[:renewal_token])
      CredentialsCache.delete(store_config, token)
    else
      _any -> :ok
    end

    %{"success" => true}
  end

  def convert_to_binary_map(user) do
    user
    |> Map.from_struct()
    |> Map.drop([:__meta__])
    |> Enum.reduce(%{}, fn {k, v}, acc ->
      if v do
        Map.put(acc, Atom.to_string(k), v)
      else
        acc
      end
    end)
  end

  def config(env) do
    [
      mod: AmpsPortal.APIAuthPlug,
      plug: AmpsPortal.APIAuthPlug,
      otp_app: :amps_portal
    ]
    |> Keyword.put(:env, env)
  end
end

defmodule Amps.Users.Vault do
  alias Amps.Users, as: Users
  import Pow.Context
  require Logger

  def host(), do: Application.fetch_env!(:amps_web, AmpsWeb.Endpoint)[:vault_addr]

  def authenticate(body) do
    vault =
      Vault.new(
        engine: Vault.Engine.KVV1,
        auth: Vault.Auth.UserPass,
        host: host()
      )

    login =
      Vault.Auth.UserPass.login(vault, %{
        username: body["username"],
        password: body["password"]
      })

    case login do
      {:ok, _token, _ttl} ->
        user = Amps.DB.find_one("users", %{username: body["username"]})

        if user["approved"] do
          Users.convert_to_user_struct(user)
        else
          {:error, nil}
        end

      {:error, _} ->
        # send_resp(conn, 406, "Unauthorized")
        {:error, nil}
    end
  end

  # Use params to look up user and verify password with `MyApp.Users.User.verify_password/2

  def create(body) do
    token = AmpsWeb.Vault.get_token(:vaulthandler)

    {:ok, vault} =
      Vault.new(
        engine: Vault.Engine.KVV1,
        auth: Vault.Auth.Token,
        host: host(),
        credentials: %{token: token}
      )
      |> Vault.auth()

    result =
      Vault.request(vault, :post, "auth/userpass/users/" |> Kernel.<>(body["username"]),
        body: %{"token_policies" => "admin,default", password: body["password"]}
      )

    IO.inspect(result)
    user = Map.drop(body, ["password"])
    user = Map.drop(user, ["confirmpswd"])

    user =
      Map.merge(user, %{"approved" => false, "role" => "Guest", "provider" => "vault"})
      |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)

    id = Amps.DB.insert("users", user)

    user = Map.put(user, :id, id)
    userstruct = struct(Amps.Users.User, user)
    {:ok, userstruct}
  end

  def update(_user, _params) do
    IO.puts("update")
    {:error, :not_implemented}
  end

  def delete(_user) do
    IO.puts("delete")
    {:error, :not_implemented}
  end
end

defmodule Amps.Users.DB do
  alias Amps.Users, as: Users
  import Pow.Context
  require Logger
  import Argon2

  def authenticate(body, config \\ nil) do
    user = Amps.DB.find_one(Users.index(config), %{"username" => body["username"]})

    case check_pass(user, body["password"], hash_key: "password") do
      {:ok, user} ->
        if user["approved"] do
          Users.convert_to_user_struct(user)
        else
          nil
        end

      {:error, reason} ->
        # IO.inspect(reason)
        nil
    end

    # Use params to look up user and verify password with `MyApp.Users.User.verify_password/2`
  end

  def create(body, config \\ nil) do
    env =
      if config do
        config[:env]
      else
        ""
      end

    create = Amps.Users.User.create(body, env)

    if create["success"] do
      {:ok, create["user"]}
    else
      {:error, create["error"]}
    end
  end

  def update(_user, _params) do
    IO.puts("update")
    {:error, :not_implemented}
  end

  def delete(id, config \\ nil) do
    env =
      if config do
        config[:env]
      else
        ""
      end

    delete = Amps.Users.User.delete(id, Users.index(config))

    if delete["success"] do
      {:ok, delete}
    else
      {:error, delete["error"]}
    end
  end
end

defmodule Amps.Users.User do
  @derive {Jason.Encoder, except: [:__meta__, :__struct__]}
  use Ecto.Schema
  use Pow.Ecto.Schema
  require PowAssent.Ecto.Schema
  import Ecto.Changeset
  import Argon2

  schema "users" do
    field(:password, :string, redact: true)
    field(:firstname, :string)
    field(:phone, :string)
    field(:email, :string)
    field(:lastname, :string)
    field(:username, :string)
    field(:approved, :boolean, default: false)
    field(:group, :string)
    field(:mailboxes, {:array, :map}, default: [])
    field(:tokens, {:array, :map}, default: [])
    field(:rules, {:array, :map}, default: [])

    field(:ufa, :map,
      default: %{
        stime: DateTime.utc_now() |> DateTime.to_iso8601(),
        debug: true,
        logfile: "./log",
        hinterval: 30,
        cinterval: 30,
        max: 100
      }
    )
  end

  # firstname: nil,
  #         phone: nil,
  #         email: nil,
  #         lastname: nil,
  #         username: nil,
  #         password: nil,
  #         role: nil,
  #         id: nil,
  #         approved: nil,
  #         group: nil,
  #         mailboxes: [],
  #         rules: [],
  #         tokens: [],
  #         ufa: %{}

  # def __changeset__() do
  #   %Amps.Users.User{}
  # end

  def reset_password_changeset(user, attrs) do
    IO.inspect(user)

    case user.username do
      nil ->
        nil

      _ ->
        _res = Amps.DB.find_one_and_update("users", %{"_id" => user.id}, attrs)
        user
    end
  end

  def create(params \\ %{}, env \\ "") do
    user =
      %Amps.Users.User{}
      |> cast(params, [
        :approved,
        :email,
        :firstname,
        :group,
        :id,
        :lastname,
        :mailboxes,
        :password,
        :phone,
        :rules,
        :tokens,
        :ufa,
        :username
      ])
      |> validate_required([:username, :email, :password])

    if user.valid? do
      user = password_hash_changeset(user) |> apply_changes()

      username = user.username

      collection = AmpsUtil.index(env, "users")

      map =
        user
        |> Map.from_struct()
        |> Map.drop([:__meta__])
        |> Enum.reduce(%{}, fn {k, v}, acc ->
          if v do
            Map.put(acc, Atom.to_string(k), v)
          else
            acc
          end
        end)

      case Amps.DB.find_one(collection, %{"username" => username}) do
        nil ->
          map

          {:ok, id} = Amps.DB.insert(collection, map)
          %{"success" => true, "id" => id, "user" => Amps.Users.get_by(%{"_id" => id})}

        _found ->
          %{"success" => false, "error" => "Duplicate Username"}
      end
    else
      errors =
        user.errors
        |> Enum.map(fn {field, {msg, _}} ->
          "#{field} #{msg}"
        end)

      %{"success" => false, "error" => errors}
    end
  end

  def update(id, params \\ %{}, env \\ "") do
    index = AmpsUtil.index(env, "users")

    user =
      Amps.Users.get_by(%{"_id" => id}, env: env)
      |> cast(params, [
        :approved,
        :email,
        :firstname,
        :group,
        :lastname,
        :mailboxes,
        :password,
        :phone,
        :rules,
        :tokens,
        :ufa
      ])
      |> validate_required([:username, :email, :password])

    if user.valid? do
      user = password_hash_changeset(user) |> apply_changes()
      IO.inspect(user)

      map =
        user
        |> Map.from_struct()
        |> Map.drop([:__meta__])
        |> Enum.reduce(%{}, fn {k, v}, acc ->
          if v do
            Map.put(acc, Atom.to_string(k), v)
          else
            acc
          end
        end)

      case Amps.DB.update(index, map, id) do
        :ok ->
          %{"success" => true, "id" => id, "user" => Amps.Users.get_by(%{"_id" => id}, env: env)}

        error ->
          %{"success" => false, "error" => error}
      end
    else
      errors =
        user.errors
        |> Enum.map(fn {field, {msg, _}} ->
          "#{field} #{msg}"
        end)

      %{"success" => false, "error" => errors}
    end
  end

  def delete(id, env \\ "") do
    index = AmpsUtil.index(env, "users")
    user = Amps.DB.find_one(index, %{"_id" => id})

    rules = user["rules"] || []

    Enum.each(rules, fn rule ->
      if rule["type"] == "download" do
        AmpsUtil.agent_rule_deletion(user, rule, env)
      end
    end)

    Amps.DB.delete_by_id(index, id)
    %{"success" => true}
  end

  def password_hash_changeset(user) do
    if Map.get(user.changes, :password) do
      %{password_hash: hashed} = add_hash(user.changes.password)
      put_change(user, :password, hashed)
    else
      user
    end
  end

  def changeset(user, _params) do
    user
  end

  def verify_password(user, password) do
    verify_pass(password, user.password)
  end

  # def user_identity_changeset(user_or_changeset, user_identity, attrs, user_id_attrs) do
  #   user_or_changeset
  #   |> Ecto.Changeset.cast(attrs, [:custom_field])
  #   |> pow_assent_user_identity_changeset(user_identity, attrs, user_id_attrs)
  # end
end
