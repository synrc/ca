defmodule CA.Profile.DSL do
  defmacro __using__(_opts) do
    quote do
      import CA.Profile.DSL
      Module.register_attribute(__MODULE__, :controls_data, accumulate: true)
      @before_compile CA.Profile.DSL
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      def controls do
        Enum.map(@controls_data, fn {id, _, _, _} -> CA.SPE.oid(id) end) |> Enum.reverse()
      end

      def specs do
        Enum.map(@controls_data, fn {id, title, desc, params} ->
          %{id: id, title: title, description: desc, parameters: Enum.reverse(params)}
        end) |> Enum.reverse()
      end
      
      def spec(id) do
        Enum.find_value(@controls_data, fn
          {^id, title, desc, params} -> %{id: id, title: title, description: desc, parameters: Enum.reverse(params)}
          _ -> nil
        end)
      end
    end
  end

  defmacro control(id, do: block) do
    quote do
      # Initialize attributes for the new control
      Module.put_attribute(__MODULE__, :current_control_title, "")
      Module.put_attribute(__MODULE__, :current_control_desc, "")
      Module.put_attribute(__MODULE__, :current_control_params, [])

      # Execute the block
      unquote(block)

      # Accumulate the result
      title = Module.get_attribute(__MODULE__, :current_control_title)
      desc = Module.get_attribute(__MODULE__, :current_control_desc)
      params = Module.get_attribute(__MODULE__, :current_control_params)
      Module.put_attribute(__MODULE__, :controls_data, {unquote(id), title, desc, params})
    end
  end

  defmacro title(text) do
    quote do
      Module.put_attribute(__MODULE__, :current_control_title, unquote(text))
    end
  end

  defmacro desc(text) do
    quote do
      Module.put_attribute(__MODULE__, :current_control_desc, unquote(text))
    end
  end

  defmacro param(name, description, opts \\ []) do
    quote do
      params = Module.get_attribute(__MODULE__, :current_control_params) || []
      Module.put_attribute(__MODULE__, :current_control_params, [{unquote(name), unquote(description), unquote(opts)} | params])
    end
  end
end
