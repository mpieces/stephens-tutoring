class UsersController < ApplicationController
  before_action :signed_in_user, only: [:edit, :update, :index, :destroy]
  before_action :correct_user, only: [:edit, :update]
  before_action :admin_user, only: :destroy

  def index
    @users = User.all
  end

  def new
    @user = User.new
  end

  def create
    @user = User.new(user_params)
    if @user.save
      @user.send_activation_email # helper method from User model
      flash[:info] = "Please check your email to activate your account."
      redirect_to root_url
    else
      render 'new'
    #   sign_in @user    # added after sessions created
    #   flash[:success] = "Welcome #{@user.first_name}!"
    #   redirect_to @user
    # else
    #   render 'new'
    end
  end

  def show
    @user = User.find(params[:id])
  end

  def edit
    @user = User.find(params[:id])
  end

  def update
    # @user = User.find(params[:id])
     # don't need this since the correct_user before filter defines @user
    if @user.update(user_params)
      flash[:success] = "Profile updated"
      # sign_in(@user) ?
      redirect_to @user
    else
      render 'edit'
    end
  end

  def destroy
    User.find(params[:id]).destroy
    flash[:success] = "User deleted"
    redirect_to users_url
  end


  private

    def user_params
      params.require(:user).permit(:first_name, :last_name, :year, :email, :phone, :address, :city, :zip, :password, :password_confirmation)
    end

     # Before filters:

     # Confirms a signed-in user
    def signed_in_user
      unless signed_in?
        store_location
        flash[:danger] = "Please log in."
        redirect_to signin_path
      end
    end
    # Confirms the correct user
    def correct_user
      @user = User.find(params[:id])
      redirect_to(root_url) unless current_user?(@user)  # defined in the Sessions helper module
    end

    def admin_user
      redirect_to(root_url) unless current_user.admin?
    end
end
